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
static void ngx_http_coraza_cleanup_instance(void *data);
static void ngx_http_coraza_cleanup_rules(void *data);

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
		ngx_log_error(NGX_LOG_ERR, (ngx_log_t *)r->connection->log, 0, "Coraza intervention: %s", intervention->action);
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

		if (early_log)
		{
			dd("intervention -- calling log handler manually with code: %d", intervention->status);
			ngx_http_coraza_log_handler(r);
			ctx->logged = 1;
		}

		if (r->header_sent)
		{
			dd("Headers are already sent. Cannot perform the redirection at this point.");
			return NGX_ERROR;
		}
		dd("intervention -- returning code: %d", intervention->status);
		return intervention->status;
	}
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

	dd("creating transaction with the following rules: '%p' -- ms: '%p'", mcf->rules_set, mmcf->modsec);

	/* Use location-specific WAF if available, otherwise fall back to main WAF */
	coraza_waf_t waf = mcf->waf != 0 ? mcf->waf : mmcf->waf;

	if (mcf->transaction_id)
	{
		if (ngx_http_complex_value(r, mcf->transaction_id, &s) != NGX_OK)
		{
			return NGX_CONF_ERROR;
		}
		ctx->coraza_transaction = coraza_new_transaction_with_id(waf, (char *)s.data);
	}
	else
	{
		ctx->coraza_transaction = coraza_new_transaction(waf);
	}

	dd("transaction created");

	ngx_http_set_ctx(r, ctx, ngx_http_coraza_module);

	cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_coraza_ctx_t));
	if (cln == NULL)
	{
		dd("failed to create the CORAZA context cleanup");
		return NGX_CONF_ERROR;
	}
	cln->handler = ngx_http_coraza_cleanup;
	cln->data = ctx;

	return ctx;
}

char *
ngx_conf_set_rules(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	int res;
	char *rules = NULL;
	ngx_str_t *value;
	ngx_http_coraza_conf_t *mcf = conf;
	ngx_http_coraza_main_conf_t *mmcf;

	value = cf->args->elts;

	if (ngx_str_to_char(value[1], rules, cf->pool) != NGX_OK) {
		dd("Failed to get the rules");
		return NGX_CONF_ERROR;
	}

	res = coraza_rules_add(mcf->config, rules);

	if (res < 0)
	{
		dd("Failed to load the rules: '%s'", rules);
		return NGX_CONF_ERROR;
	}

	mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_coraza_module);
	mmcf->rules_inline += 1;

	return NGX_CONF_OK;
}

char *
ngx_conf_set_rules_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	int res;
	char *rules_file = NULL;
	ngx_str_t *value;
	ngx_http_coraza_conf_t *mcf = conf;
	ngx_http_coraza_main_conf_t *mmcf;

	value = cf->args->elts;

	if (ngx_str_to_char(value[1], rules_file, cf->pool) != NGX_OK) {
		dd("Failed to get the rules_file");
		return NGX_CONF_ERROR;
	}

	res = coraza_rules_add_file(mcf->config, rules_file);

	if (res < 0)
	{
		dd("Failed to load the rules from: '%s'", rules_file);
		return NGX_CONF_ERROR;
	}

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
	NULL,					  /* init process */
	NULL,					  /* init thread */
	NULL,					  /* exit thread */
	NULL,					  /* exit process */
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
	ngx_pool_cleanup_t *cln;
	ngx_http_coraza_main_conf_t *conf;

	conf = (ngx_http_coraza_main_conf_t *)ngx_pcalloc(cf->pool,
													  sizeof(ngx_http_coraza_main_conf_t));

	if (conf == NULL)
	{
		return NGX_CONF_ERROR;
	}

	/*
	 * set by ngx_pcalloc():
	 *
	 *     conf->waf = NULL;
	 *     conf->pool = NULL;
	 *     conf->rules_inline = 0;
	 *     conf->rules_file = 0;
	 *     conf->rules_remote = 0;
	 */

	cln = ngx_pool_cleanup_add(cf->pool, 0);
	if (cln == NULL)
	{
		return NGX_CONF_ERROR;
	}

	cln->handler = ngx_http_coraza_cleanup_instance;
	cln->data = conf;

	conf->pool = cf->pool;

	/* Create our CORAZA config */
	conf->config = coraza_new_waf_config();
	if (conf->config == 0)
	{
		dd("failed to create the CORAZA config");
		return NGX_CONF_ERROR;
	}

	/* WAF will be created later after rules are loaded */
	conf->waf = 0;

	dd("main conf created at: '%p', config is: '%p'", conf, conf->config);

	return conf;
}

static char *
ngx_http_coraza_init_main_conf(ngx_conf_t *cf, void *conf)
{
	char *error = NULL;
	ngx_http_coraza_main_conf_t *mmcf;
	mmcf = (ngx_http_coraza_main_conf_t *)conf;

	/* Create WAF from config now that rules are loaded */
	if (mmcf->config != 0) {
		mmcf->waf = coraza_new_waf(mmcf->config, &error);
		if (mmcf->waf == 0)
		{
			if (error != NULL) {
				ngx_log_error(NGX_LOG_ERR, cf->log, 0,
							  "Failed to create CORAZA WAF: %s", error);
			} else {
				ngx_log_error(NGX_LOG_ERR, cf->log, 0,
							  "Failed to create CORAZA WAF");
			}
			return NGX_CONF_ERROR;
		}
	}

	ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
				  "rules loaded inline/local: %ui/%ui",
				  mmcf->rules_inline,
				  mmcf->rules_file);

	return NGX_CONF_OK;
}

static void *
ngx_http_coraza_create_conf(ngx_conf_t *cf)
{
	ngx_pool_cleanup_t *cln;
	ngx_http_coraza_conf_t *conf;

	conf = (ngx_http_coraza_conf_t *)ngx_pcalloc(cf->pool,
												 sizeof(ngx_http_coraza_conf_t));

	if (conf == NULL)
	{
		dd("Failed to allocate space for CORAZA configuration");
		return NGX_CONF_ERROR;
	}

	/*
	 * set by ngx_pcalloc():
	 *
	 *     conf->enable = 0;
	 *     conf->sanity_checks_enabled = 0;
	 *     conf->config = 0;
	 *     conf->waf = 0;
	 *     conf->pool = NULL;
	 *     conf->transaction_id = NULL;
	 */

	conf->enable = NGX_CONF_UNSET;
	conf->config = coraza_new_waf_config();
	if (conf->config == 0)
	{
		dd("failed to create the CORAZA config");
		return NGX_CONF_ERROR;
	}
	conf->waf = 0;
	conf->pool = cf->pool;
	conf->transaction_id = NGX_CONF_UNSET_PTR;
#if defined(CORAZA_SANITY_CHECKS) && (CORAZA_SANITY_CHECKS)
	conf->sanity_checks_enabled = NGX_CONF_UNSET;
#endif

	cln = ngx_pool_cleanup_add(cf->pool, 0);
	if (cln == NULL)
	{
		dd("failed to create the CORAZA configuration cleanup");
		return NGX_CONF_ERROR;
	}

	cln->handler = ngx_http_coraza_cleanup_rules;
	cln->data = conf;

	dd("conf created at: '%p'", conf);

	return conf;
}

static char *
ngx_http_coraza_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_coraza_conf_t *p = parent;
	ngx_http_coraza_conf_t *c = child;
#if defined(CORAZA_DDEBUG) && (CORAZA_DDEBUG)
	ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	dd("merging loc config [%s] - parent: '%p' child: '%p'",
		clcf->name.data, parent,
		child);
#endif
	char *error = NULL;

	dd("                  state - parent: '%d' child: '%d'",
	   (int)c->enable, (int)p->enable);

	ngx_conf_merge_value(c->enable, p->enable, 0);
	ngx_conf_merge_ptr_value(c->transaction_id, p->transaction_id, NULL);
#if defined(CORAZA_SANITY_CHECKS) && (CORAZA_SANITY_CHECKS)
	ngx_conf_merge_value(c->sanity_checks_enabled, p->sanity_checks_enabled, 0);
#endif

	/* Create WAF from child config if not already created */
	if (c->config != 0 && c->waf == 0) {
		c->waf = coraza_new_waf(c->config, &error);
		if (c->waf == 0)
		{
			if (error != NULL) {
				ngx_log_error(NGX_LOG_ERR, cf->log, 0,
							  "Failed to create child CORAZA WAF: %s", error);
				return error;
			}
			return NGX_CONF_ERROR;
		}
	}

	/* If child has no WAF, use parent's WAF */
	if (c->waf == 0 && p->waf != 0) {
		c->waf = p->waf;
		c->config = p->config;
	}

	return NGX_CONF_OK;
}

static void
ngx_http_coraza_cleanup_instance(void *data)
{
	ngx_http_coraza_main_conf_t *mmcf;

	mmcf = (ngx_http_coraza_main_conf_t *)data;

	dd("deleting a main conf -- waf is: \"%p\", config is: \"%p\"", mmcf->waf, mmcf->config);

	if (mmcf->waf != 0) {
		coraza_free_waf(mmcf->waf);
		mmcf->waf = 0;
	}

	if (mmcf->config != 0) {
		coraza_free_waf_config(mmcf->config);
		mmcf->config = 0;
	}
}

static void
ngx_http_coraza_cleanup_rules(void *data)
{
	ngx_http_coraza_conf_t *mcf;

	mcf = (ngx_http_coraza_conf_t *)data;

	dd("deleting a loc conf -- waf is: \"%p\", config is: \"%p\"", mcf->waf, mcf->config);

	/* Note: WAF may be shared from parent, only free config here */
	if (mcf->config != 0) {
		coraza_free_waf_config(mcf->config);
		mcf->config = 0;
	}
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
