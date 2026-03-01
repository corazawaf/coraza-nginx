/*
 * Coraza connector for nginx, http://www.coraza.io/
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 */

#ifndef CORAZA_DDEBUG
#define CORAZA_DDEBUG 0
#endif
#include "ddebug.h"

#include "ngx_http_coraza_common.h"
#include "stdio.h"
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static ngx_int_t ngx_http_coraza_init(ngx_conf_t *cf);
static void *ngx_http_coraza_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_coraza_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_coraza_create_conf(ngx_conf_t *cf);
static char *ngx_http_coraza_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_coraza_init_process(ngx_cycle_t *cycle);
static void ngx_http_coraza_exit_process(ngx_cycle_t *cycle);

ngx_inline ngx_int_t
ngx_http_coraza_process_intervention(coraza_transaction_t transaction, ngx_http_request_t *r, ngx_int_t early_log)
{
	coraza_intervention_t *intervention;
	ngx_http_coraza_ctx_t *ctx = NULL;

	dd("processing intervention");

	ctx = ngx_http_get_module_ctx(r, ngx_http_coraza_module);
	if (ctx == NULL)
	{
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	intervention = coraza_intervention(transaction);

	if (intervention == NULL)
	{
		dd("nothing to do");
		return NGX_OK;
	}

	if (intervention->action != NULL)
	{
		dd("intervention action: %s", intervention->action);
	}

	if (intervention->status != 200)
	{
		/**
		 * FIXME: this will bring proper response code to audit log in case
		 * when e.g. error_page redirect was triggered, but there still won't be another
		 * required pieces like response headers etc.
		 *
		 */
		coraza_update_status_code(ctx->coraza_transaction, intervention->status);

		if (ctx->transaction_id.len > 0) {
			ngx_log_error(NGX_LOG_ERR, (ngx_log_t *)r->connection->log, 0,
				"Coraza: Access denied with code %d, unique_id \"%V\"",
				intervention->status, &ctx->transaction_id);
		}

		if (early_log)
		{
			dd("intervention -- calling log handler manually with code: %d", intervention->status);
			ngx_http_coraza_log_handler(r);
			ctx->logged = 1;
		}

		if (r->header_sent)
		{
			dd("Headers are already sent. Cannot perform the redirection at this point.");
			coraza_free_intervention(intervention);
			return NGX_ERROR;
		}

		if (intervention->data != NULL
			&& (intervention->status == NGX_HTTP_MOVED_PERMANENTLY
				|| intervention->status == NGX_HTTP_MOVED_TEMPORARILY
				|| intervention->status == NGX_HTTP_SEE_OTHER
				|| intervention->status == NGX_HTTP_TEMPORARY_REDIRECT
				|| intervention->status == 308))
		{
			ngx_table_elt_t *h;
			h = ngx_list_push(&r->headers_out.headers);
			if (h != NULL)
			{
				size_t len = ngx_strlen(intervention->data);
				h->hash = 0;
				ngx_str_set(&h->key, "Location");
				h->value.len = 0;
				h->value.data = ngx_pnalloc(r->pool, len);
				if (h->value.data != NULL)
				{
					ngx_memcpy(h->value.data, intervention->data, len);
					h->value.len = len;
					h->hash = 1;
					r->headers_out.location = h;
				}
			}
		}

		dd("intervention -- returning code: %d", intervention->status);
		ngx_int_t status = intervention->status;
		coraza_free_intervention(intervention);
		return status;
	}
	coraza_free_intervention(intervention);
	return NGX_OK;
}

void ngx_http_coraza_cleanup(void *data)
{
	ngx_http_coraza_ctx_t *ctx;

	ctx = (ngx_http_coraza_ctx_t *)data;

	if (coraza_free_transaction(ctx->coraza_transaction) != NGX_OK) {
		dd("cleanup -- transaction free failed: %d", res);
	};
}

ngx_inline ngx_http_coraza_ctx_t *
ngx_http_coraza_create_ctx(ngx_http_request_t *r)
{
	ngx_str_t s;
	ngx_pool_cleanup_t *cln;
	ngx_http_coraza_ctx_t *ctx;
	ngx_http_coraza_conf_t *mcf;
	ngx_http_coraza_main_conf_t *mmcf;

	ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_coraza_ctx_t));
	if (ctx == NULL)
	{
		dd("failed to allocate memory for the context.");
		return NULL;
	}

	mmcf = ngx_http_get_module_main_conf(r, ngx_http_coraza_module);
	mcf = ngx_http_get_module_loc_conf(r, ngx_http_coraza_module);

	dd("creating transaction with the following WAFs: loc='%p' -- main='%p'", mcf->waf, mmcf->waf);

	/* Use location-specific WAF if available, otherwise fall back to main WAF */
	coraza_waf_t waf = mcf->waf != 0 ? mcf->waf : mmcf->waf;

	if (waf == 0)
	{
		dd("WAF not initialized");
		return NULL;
	}

	if (mcf->transaction_id)
	{
		if (ngx_http_complex_value(r, mcf->transaction_id, &s) != NGX_OK)
		{
			return NULL;
		}
		ctx->coraza_transaction = coraza_new_transaction_with_id(waf, (char *)s.data);
		ctx->transaction_id.data = ngx_pstrdup(r->pool, &s);
		ctx->transaction_id.len = s.len;
	}
	else
	{
		ctx->coraza_transaction = coraza_new_transaction(waf);
		ngx_str_null(&ctx->transaction_id);
	}

	dd("transaction created");

	ngx_http_set_ctx(r, ctx, ngx_http_coraza_module);

	cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_coraza_ctx_t));
	if (cln == NULL)
	{
		dd("failed to create the CORAZA context cleanup");
		return NULL;
	}
	cln->handler = ngx_http_coraza_cleanup;
	cln->data = ctx;

	return ctx;
}

char *
ngx_conf_set_rules(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_str_t *value;
	ngx_http_coraza_conf_t *mcf = conf;
	ngx_http_coraza_main_conf_t *mmcf;
	ngx_http_coraza_rule_entry_t *entry;

	value = cf->args->elts;

	/* Store the rule string for deferred replay in init_process */
	entry = ngx_array_push(mcf->rules);
	if (entry == NULL) {
		return NGX_CONF_ERROR;
	}

	entry->type = NGX_CORAZA_RULE_INLINE;
	entry->value.len = value[1].len;
	entry->value.data = ngx_pstrdup(cf->pool, &value[1]);
	if (entry->value.data == NULL) {
		return NGX_CONF_ERROR;
	}

	mcf->has_rules = 1;

	mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_coraza_module);
	mmcf->rules_inline += 1;

	return NGX_CONF_OK;
}

char *
ngx_conf_set_rules_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_str_t *value;
	ngx_http_coraza_conf_t *mcf = conf;
	ngx_http_coraza_main_conf_t *mmcf;
	ngx_http_coraza_rule_entry_t *entry;

	value = cf->args->elts;

	/* Store the file path for deferred replay in init_process */
	entry = ngx_array_push(mcf->rules);
	if (entry == NULL) {
		return NGX_CONF_ERROR;
	}

	entry->type = NGX_CORAZA_RULE_FILE;
	entry->value.len = value[1].len;
	entry->value.data = ngx_pstrdup(cf->pool, &value[1]);
	if (entry->value.data == NULL) {
		return NGX_CONF_ERROR;
	}

	mcf->has_rules = 1;

	mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_coraza_module);
	mmcf->rules_file += 1;

	return NGX_CONF_OK;
}

char *ngx_conf_set_transaction_id(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_str_t *value;
	ngx_http_complex_value_t cv;
	ngx_http_compile_complex_value_t ccv;
	ngx_http_coraza_conf_t *mcf = conf;

	value = cf->args->elts;

	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

	ccv.cf = cf;
	ccv.value = &value[1];
	ccv.complex_value = &cv;
	ccv.zero = 1;

	if (ngx_http_compile_complex_value(&ccv) != NGX_OK)
	{
		return NGX_CONF_ERROR;
	}

	mcf->transaction_id = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
	if (mcf->transaction_id == NULL)
	{
		return NGX_CONF_ERROR;
	}

	*mcf->transaction_id = cv;

	return NGX_CONF_OK;
}

static ngx_command_t ngx_http_coraza_commands[] = {
	{ngx_string("coraza"),
	 NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG,
	 ngx_conf_set_flag_slot,
	 NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_coraza_conf_t, enable),
	 NULL},
	{ngx_string("coraza_rules"),
	 NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
	 ngx_conf_set_rules,
	 NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_coraza_conf_t, enable),
	 NULL},
	{ngx_string("coraza_rules_file"),
	 NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
	 ngx_conf_set_rules_file,
	 NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_coraza_conf_t, enable),
	 NULL},
	{ngx_string("coraza_transaction_id"),
	 NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF | NGX_CONF_1MORE,
	 ngx_conf_set_transaction_id,
	 NGX_HTTP_LOC_CONF_OFFSET,
	 0,
	 NULL},
	ngx_null_command};

static ngx_http_module_t ngx_http_coraza_ctx = {
	NULL,				  /* preconfiguration */
	ngx_http_coraza_init, /* postconfiguration */

	ngx_http_coraza_create_main_conf, /* create main configuration */
	ngx_http_coraza_init_main_conf,	  /* init main configuration */

	NULL, /* create server configuration */
	NULL, /* merge server configuration */

	ngx_http_coraza_create_conf, /* create location configuration */
	ngx_http_coraza_merge_conf	 /* merge location configuration */
};

ngx_module_t ngx_http_coraza_module = {
	NGX_MODULE_V1,
	&ngx_http_coraza_ctx,	  /* module context */
	ngx_http_coraza_commands, /* module directives */
	NGX_HTTP_MODULE,		  /* module type */
	NULL,					  /* init master */
	NULL,					  /* init module */
	ngx_http_coraza_init_process, /* init process */
	NULL,					  /* init thread */
	NULL,					  /* exit thread */
	ngx_http_coraza_exit_process, /* exit process */
	NULL,					  /* exit master */
	NGX_MODULE_V1_PADDING};

static ngx_int_t
ngx_http_coraza_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt *h_rewrite;
	ngx_http_handler_pt *h_preaccess;
	ngx_http_handler_pt *h_log;
	ngx_http_core_main_conf_t *cmcf;
	int rc = 0;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
	if (cmcf == NULL)
	{
		dd("We are not sure how this returns, NGINX doesn't seem to think it will ever be null");
		return NGX_ERROR;
	}
	/**
	 *
	 * Seems like we cannot do this very same thing with
	 * NGX_HTTP_FIND_CONFIG_PHASE. it does not seems to
	 * be an array. Our next option is the REWRITE.
	 *
	 * TODO: check if we can hook prior to NGX_HTTP_REWRITE_PHASE phase.
	 *
	 */
	h_rewrite = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
	if (h_rewrite == NULL)
	{
		dd("Not able to create a new NGX_HTTP_REWRITE_PHASE handle");
		return NGX_ERROR;
	}
	*h_rewrite = ngx_http_coraza_rewrite_handler;

	/**
	 *
	 * Processing the request body on the preaccess phase.
	 *
	 * TODO: check if hook into separated phases is the best thing to do.
	 *
	 */
	h_preaccess = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
	if (h_preaccess == NULL)
	{
		dd("Not able to create a new NGX_HTTP_PREACCESS_PHASE handle");
		return NGX_ERROR;
	}
	*h_preaccess = ngx_http_coraza_pre_access_handler;

	/**
	 * Process the log phase.
	 *
	 * TODO: check if the log phase happens like it happens on Apache.
	 *       check if last phase will not hold the request.
	 *
	 */
	h_log = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
	if (h_log == NULL)
	{
		dd("Not able to create a new NGX_HTTP_LOG_PHASE handle");
		return NGX_ERROR;
	}
	*h_log = ngx_http_coraza_log_handler;

	rc = ngx_http_coraza_header_filter_init();
	if (rc != NGX_OK)
	{
		return rc;
	}

	rc = ngx_http_coraza_body_filter_init();
	if (rc != NGX_OK)
	{
		return rc;
	}

	return NGX_OK;
}

static void *
ngx_http_coraza_create_main_conf(ngx_conf_t *cf)
{
	ngx_http_coraza_main_conf_t *conf;

	conf = (ngx_http_coraza_main_conf_t *)ngx_pcalloc(cf->pool,
													  sizeof(ngx_http_coraza_main_conf_t));

	if (conf == NULL)
	{
		return NULL;
	}

	/*
	 * set by ngx_pcalloc():
	 *
	 *     conf->waf = 0;
	 *     conf->pool = NULL;
	 *     conf->rules_inline = 0;
	 *     conf->rules_file = 0;
	 *     conf->rules_remote = 0;
	 */

	conf->pool = cf->pool;

	conf->rules = ngx_array_create(cf->pool, 4,
								   sizeof(ngx_http_coraza_rule_entry_t));
	if (conf->rules == NULL) {
		return NULL;
	}

	conf->loc_confs = ngx_array_create(cf->pool, 8,
										sizeof(ngx_http_coraza_conf_t *));
	if (conf->loc_confs == NULL) {
		return NULL;
	}

	/* No coraza_* calls here — library not loaded yet */

	dd("main conf created at: '%p'", conf);

	return conf;
}

static char *
ngx_http_coraza_init_main_conf(ngx_conf_t *cf, void *conf)
{
	ngx_http_coraza_main_conf_t *mmcf;
	mmcf = (ngx_http_coraza_main_conf_t *)conf;

	/* No coraza_* calls — WAFs are created in init_process after fork */

	ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
				  "coraza: rules collected inline/local: %ui/%ui "
				  "(WAFs will be created in worker processes)",
				  mmcf->rules_inline,
				  mmcf->rules_file);

	return NGX_CONF_OK;
}

static void *
ngx_http_coraza_create_conf(ngx_conf_t *cf)
{
	ngx_http_coraza_conf_t *conf;

	conf = (ngx_http_coraza_conf_t *)ngx_pcalloc(cf->pool,
												 sizeof(ngx_http_coraza_conf_t));

	if (conf == NULL)
	{
		dd("Failed to allocate space for CORAZA configuration");
		return NULL;
	}

	/*
	 * set by ngx_pcalloc():
	 *
	 *     conf->enable = 0;
	 *     conf->waf = 0;
	 *     conf->pool = NULL;
	 *     conf->transaction_id = NULL;
	 *     conf->has_rules = 0;
	 */

	conf->enable = NGX_CONF_UNSET;
	conf->waf = 0;
	conf->pool = cf->pool;
	conf->transaction_id = NGX_CONF_UNSET_PTR;

	conf->rules = ngx_array_create(cf->pool, 4,
								   sizeof(ngx_http_coraza_rule_entry_t));
	if (conf->rules == NULL) {
		return NULL;
	}

	/* No coraza_* calls or cleanup handlers — library not loaded yet */

	dd("conf created at: '%p'", conf);

	return conf;
}

static char *
ngx_http_coraza_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_coraza_conf_t *p = parent;
	ngx_http_coraza_conf_t *c = child;
	ngx_http_coraza_main_conf_t *mmcf;
	ngx_http_coraza_conf_t **lcp;

#if defined(CORAZA_DDEBUG) && (CORAZA_DDEBUG)
	ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	dd("merging loc config [%s] - parent: '%p' child: '%p'",
		clcf->name.data, parent,
		child);
#endif

	dd("                  state - parent: '%d' child: '%d'",
	   (int)c->enable, (int)p->enable);

	ngx_conf_merge_value(c->enable, p->enable, 0);
	ngx_conf_merge_ptr_value(c->transaction_id, p->transaction_id, NULL);
#if defined(CORAZA_SANITY_CHECKS) && (CORAZA_SANITY_CHECKS)
	ngx_conf_merge_value(c->sanity_checks_enabled, p->sanity_checks_enabled, 0);
#endif

	/*
	 * Prepend parent rules to child rules — this produces the same rule
	 * ordering as the old coraza_rules_merge() approach.
	 */
	if (p->rules->nelts > 0) {
		if (c->rules->nelts > 0) {
			/* Child has its own rules: prepend parent's rules before them */
			ngx_array_t *merged;
			ngx_uint_t total = p->rules->nelts + c->rules->nelts;

			merged = ngx_array_create(cf->pool, total,
									  sizeof(ngx_http_coraza_rule_entry_t));
			if (merged == NULL) {
				return NGX_CONF_ERROR;
			}

			ngx_http_coraza_rule_entry_t *dst;

			dst = ngx_array_push_n(merged, p->rules->nelts);
			if (dst == NULL) {
				return NGX_CONF_ERROR;
			}
			ngx_memcpy(dst,
					   p->rules->elts,
					   p->rules->nelts * sizeof(ngx_http_coraza_rule_entry_t));

			dst = ngx_array_push_n(merged, c->rules->nelts);
			if (dst == NULL) {
				return NGX_CONF_ERROR;
			}
			ngx_memcpy(dst,
					   c->rules->elts,
					   c->rules->nelts * sizeof(ngx_http_coraza_rule_entry_t));

			c->rules = merged;
			c->has_rules = 1;
		} else {
			/* Child has no own rules: share parent's rules pointer */
			c->rules = p->rules;
			if (p->has_rules) {
				c->has_rules = 1;
			}
		}
	}

	/* Track each loc_conf so init_process can iterate them */
	mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_coraza_module);
	lcp = ngx_array_push(mmcf->loc_confs);
	if (lcp == NULL) {
		return NGX_CONF_ERROR;
	}
	*lcp = c;

	return NGX_CONF_OK;
}


/* ------------------------------------------------------------------ */
/* Helper: build a WAF from a rules array                              */
/* ------------------------------------------------------------------ */

static coraza_waf_t
ngx_http_coraza_build_waf(ngx_array_t *rules, ngx_log_t *log)
{
	ngx_http_coraza_rule_entry_t *entries;
	coraza_waf_config_t config;
	coraza_waf_t waf;
	char *error = NULL;
	char *cstr;
	ngx_uint_t i;

	if (rules == NULL || rules->nelts == 0) {
		return 0;
	}

	config = coraza_new_waf_config();
	if (config == 0) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
					  "coraza: failed to create WAF config");
		return 0;
	}

	entries = rules->elts;
	for (i = 0; i < rules->nelts; i++) {
		/* Build a null-terminated C string from the ngx_str_t */
		cstr = malloc(entries[i].value.len + 1);
		if (cstr == NULL) {
			ngx_log_error(NGX_LOG_ERR, log, 0,
						  "coraza: malloc failed for rule string");
			coraza_free_waf_config(config);
			return 0;
		}
		ngx_memcpy(cstr, entries[i].value.data, entries[i].value.len);
		cstr[entries[i].value.len] = '\0';

		if (entries[i].type == NGX_CORAZA_RULE_INLINE) {
			if (coraza_rules_add(config, cstr) < 0) {
				ngx_log_error(NGX_LOG_ERR, log, 0,
							  "coraza: failed to add inline rule: \"%s\"", cstr);
				free(cstr);
				coraza_free_waf_config(config);
				return 0;
			}
		} else {
			if (coraza_rules_add_file(config, cstr) < 0) {
				ngx_log_error(NGX_LOG_ERR, log, 0,
							  "coraza: failed to add rules file: \"%s\"", cstr);
				free(cstr);
				coraza_free_waf_config(config);
				return 0;
			}
		}
		free(cstr);
	}

	waf = coraza_new_waf(config, &error);
	coraza_free_waf_config(config);

	if (waf == 0) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
					  "coraza: failed to create WAF: %s",
					  error ? error : "unknown error");
		return 0;
	}

	return waf;
}


/* ------------------------------------------------------------------ */
/* init_process: called in each worker after fork                      */
/* ------------------------------------------------------------------ */

static ngx_int_t
ngx_http_coraza_init_process(ngx_cycle_t *cycle)
{
	ngx_http_coraza_main_conf_t *mmcf;
	ngx_http_coraza_conf_t **loc_confs;
	ngx_uint_t i;

	/* Step 1: load libcoraza.so — Go runtime initializes fresh here */
	if (ngx_http_coraza_dl_open(cycle->log) != NGX_OK) {
		return NGX_ERROR;
	}

	mmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_coraza_module);
	if (mmcf == NULL) {
		return NGX_OK;
	}

	/* Step 2: build main WAF (always create one — acts as fallback for
	 * locations with coraza=on but no rules in the hierarchy) */
	if (mmcf->rules->nelts > 0) {
		mmcf->waf = ngx_http_coraza_build_waf(mmcf->rules, cycle->log);
	} else {
		/* Empty WAF — transactions pass through without rules */
		coraza_waf_config_t cfg = coraza_new_waf_config();
		if (cfg != 0) {
			char *err = NULL;
			mmcf->waf = coraza_new_waf(cfg, &err);
			coraza_free_waf_config(cfg);
		}
	}
	if (mmcf->waf == 0) {
		ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
					  "coraza: failed to build main WAF in worker");
		return NGX_ERROR;
	}
	ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
				  "coraza: main WAF initialized with %d rules",
				  coraza_rules_count(mmcf->waf));

	/* Step 3: build WAF for each loc_conf */
	loc_confs = mmcf->loc_confs->elts;
	for (i = 0; i < mmcf->loc_confs->nelts; i++) {
		ngx_http_coraza_conf_t *lcf = loc_confs[i];

		if (!lcf->has_rules || lcf->rules->nelts == 0) {
			continue;
		}

		/* If this loc_conf shares a rules pointer with main or another
		 * loc_conf that we already built, reuse that WAF. */
		if (lcf->rules == mmcf->rules && mmcf->waf != 0) {
			lcf->waf = mmcf->waf;
			continue;
		}

		/* Check if another loc_conf already built this exact rules array */
		ngx_uint_t j;
		ngx_int_t found = 0;
		for (j = 0; j < i; j++) {
			if (loc_confs[j]->rules == lcf->rules && loc_confs[j]->waf != 0) {
				lcf->waf = loc_confs[j]->waf;
				found = 1;
				break;
			}
		}
		if (found) {
			continue;
		}

		lcf->waf = ngx_http_coraza_build_waf(lcf->rules, cycle->log);
		if (lcf->waf == 0) {
			ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
						  "coraza: failed to build loc WAF in worker");
			return NGX_ERROR;
		}
		ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
					  "coraza: loc WAF initialized with %d rules",
					  coraza_rules_count(lcf->waf));
	}

	ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
				  "coraza: WAFs initialized in worker process %P",
				  ngx_pid);

	return NGX_OK;
}


/* ------------------------------------------------------------------ */
/* exit_process: called when a worker shuts down                       */
/* ------------------------------------------------------------------ */

static void
ngx_http_coraza_exit_process(ngx_cycle_t *cycle)
{
	ngx_http_coraza_main_conf_t *mmcf;
	ngx_http_coraza_conf_t **loc_confs;
	ngx_uint_t i;

	mmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_coraza_module);
	if (mmcf == NULL) {
		ngx_http_coraza_dl_close(cycle->log);
		return;
	}

	/* Free loc_conf WAFs, skipping shared ones.
	 * Walk the array twice: first pass frees unique WAFs,
	 * second pass zeroes all pointers.  This avoids a double-free
	 * bug where zeroing waf in the first pass defeats the dedup check
	 * for later loc_confs that share the same handle. */
	loc_confs = mmcf->loc_confs->elts;
	for (i = 0; i < mmcf->loc_confs->nelts; i++) {
		ngx_http_coraza_conf_t *lcf = loc_confs[i];

		if (lcf->waf == 0 || lcf->waf == mmcf->waf) {
			continue;
		}

		/* Check if an earlier loc_conf already freed this WAF */
		ngx_uint_t j;
		ngx_int_t shared = 0;
		for (j = 0; j < i; j++) {
			if (loc_confs[j]->waf == lcf->waf) {
				shared = 1;
				break;
			}
		}
		if (!shared) {
			coraza_free_waf(lcf->waf);
		}
	}
	for (i = 0; i < mmcf->loc_confs->nelts; i++) {
		loc_confs[i]->waf = 0;
	}

	/* Free main WAF */
	if (mmcf->waf != 0) {
		coraza_free_waf(mmcf->waf);
		mmcf->waf = 0;
	}

	ngx_http_coraza_dl_close(cycle->log);
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
