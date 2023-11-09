⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️
THIS MODULE IS NOT PRODUCTION READY
⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️

👉 YOU CANNOT CREATE ISSUES HERE, BUT YOU CAN CREATE PULL REQUESTS FIXING PROBLEMS 👈

🙏 DO NOT CREATE PULL REQUESTS TO COMPLAIN ABOUT THINGS NOT WORKING. THIS IS EXPERIMENTAL AND NO WORK IS BEING DONE HERE. 

👉YOU ARE WELCOME TO WORK ON IT AND SEND PULL REQUESTS! 👈

[![Compile module](https://github.com/corazawaf/coraza-nginx/actions/workflows/build.yml/badge.svg)](https://github.com/corazawaf/coraza-nginx/actions/workflows/build.yml)

# Coraza NGINX Connector

The coraza-nginx connector is the connection point between nginx and libcoraza. The module simply serves as a layer of communication between nginx and Coraza.

# Compilation

If you have any doubts, please read the [GitHub build Action](https://github.com/corazawaf/coraza-nginx/blob/master/.github/workflows/build.yml) for additional information.

Before compile this software make sure that you have libcoraza installed.
You can download it from the [libcoraza git repository](https://github.com/corazawaf/libcoraza). For information pertaining to the compilation and installation of libcoraza please consult the documentation provided along with it.

With libcoraza installed, you can proceed with the installation of the coraza-nginx connector, which follows the nginx third-party module installation procedure. From the nginx source directory:

```
./configure --add-module=/path/to/coraza-nginx
```

Or, to build a dynamic module:

```
./configure --add-dynamic-module=/path/to/coraza-nginx --with-compat
```

Note that when building a dynamic module, your nginx source version
needs to match the version of nginx you're compiling this for.

Further information about nginx third-party add-ons support are available here:
http://wiki.nginx.org/3rdPartyModules


# Usage

coraza for nginx extends your nginx configuration directives.
It adds four new directives and they are:

coraza
------
**syntax:** *coraza on | off*

**context:** *http, server, location*

**default:** *off*

Turns on or off Coraza functionality.
Note that this configuration directive is no longer related to the SecRule state.
Instead, it now serves solely as an nginx flag to enable or disable the module.

coraza_rules_file
----------------------
**syntax:** *coraza_rules_file &lt;path to rules file&gt;*

**context:** *http, server, location*

**default:** *no*

Specifies the location of the coraza configuration file, e.g.:

```nginx
server {
    coraza on;
    location / {
        root /var/www/html;
        coraza_rules_file /etc/my_coraza_rules.conf;
    }
}
```

coraza_rules_remote
------------------------
**syntax:** *coraza_rules_remote &lt;key&gt; &lt;URL to rules&gt;*

**context:** *http, server, location*

**default:** *no*

Specifies from where (on the internet) a coraza configuration file will be downloaded.
It also specifies the key that will be used to authenticate to that server:

```nginx
server {
    coraza on;
    location / {
        root /var/www/html;
        coraza_rules_remote my-server-key https://my-own-server/rules/download;
    }
}
```

coraza_rules
-----------------
**syntax:** *coraza_rules &lt;coraza rule&gt;*

**context:** *http, server, location*

**default:** *no*

Allows for the direct inclusion of a coraza rule into the nginx configuration.
The following example is loading rules from a file and injecting specific configurations per directory/alias:

```nginx
server {
    coraza on;
    location / {
        root /var/www/html;
        coraza_rules_file /etc/my_coraza_rules.conf;
    }
    location /ops {
        root /var/www/html/opts;
        coraza_rules '
          SecRuleEngine On
          SecDebugLog /tmp/coraza_debug.log
          SecDebugLogLevel 9
          SecRuleRemoveById 10
        ';
    }
}
```

coraza_transaction_id
--------------------------
**syntax:** *coraza_transaction_id string*

**context:** *http, server, location*

**default:** *no*

Allows to pass transaction ID from nginx instead of generating it in the library.
This can be useful for tracing purposes, e.g. consider this configuration:

```nginx
log_format extended '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent" $request_id';

server {
    server_name host1;
    coraza on;
    coraza_transaction_id "host1-$request_id";
    access_log logs/host1-access.log extended;
    error_log logs/host1-error.log;
    location / {
        ...
    }
}

server {
    server_name host2;
    coraza on;
    coraza_transaction_id "host2-$request_id";
    access_log logs/host2-access.log extended;
    error_log logs/host2-error.log;
    location / {
        ...
    }
}
```

Using a combination of log_format and coraza_transaction_id you will
be able to find correlations between access log and error log entries
using the same unique identificator.

String can contain variables.


# Contributing

As an open source project we invite (and encourage) anyone from the community to contribute to our project. This may take the form of: new
functionality, bug fixes, bug reports, beginners user support, and anything else that you
are willing to help with. Thank you.


## Providing Patches

We prefer to have your patch within the GitHub infrastructure to facilitate our
review work, and our QA integration. GitHub provides an excellent
documentation on how to perform “Pull Requests”. More information available
here: https://help.github.com/articles/using-pull-requests/

Please respect the coding style in use. Pull requests can include various commits, so
provide one fix or one functionality per commit. Do not change anything outside
the scope of your target work (e.g. coding style in a function that you have
passed by). 

### Don’t know where to start?

Within our code there are various items marked as TODO or FIXME that may need
your attention. Check the list of items by performing a grep:

```
$ cd /path/to/coraza-nginx
$ egrep -Rin "TODO|FIXME" -R *
```

You may also take a look at recent bug reports and open issues to get an idea of what kind of help we are looking for.

### Testing your patch

Along with the manual testing, we strongly recommend that you to use the nginx test
utility to make sure that you patch does not adversely affect the behavior or performance of nginx. 

The nginx tests are available on: http://hg.nginx.org/nginx-tests/ 

To use those tests, make sure you have the Perl utility prove (part of Perl 5)
and proceed with the following commands:

```
$ cp /path/to/coraza-nginx/tests/* /path/to/nginx/test/repository
$ cd /path/to/nginx/test/repository
$ TEST_NGINX_BINARY=/path/to/your/nginx prove .
```

If you are facing problems getting your added functionality to pass all the nginx tests, feel free to contact us or the nginx mailing list at: http://nginx.org/en/support.html

### Debugging 

We respect the nginx debugging schema. By using the configuration option
"--with-debug" during the nginx configuration you will also be enabling the
connector's debug messages. Core dumps and crashes are expected to be debugged
in the same fashion that is used to debug nginx. For further information,
please check the nginx debugging information: http://wiki.nginx.org/Debugging


## Reporting Issues

If you are facing a configuration issue or if something is not working as you
expect it to be, please use coraza user’s mailing list. Issues on GitHub
are also welcome, but we prefer to have users question on the mailing list first,
where you can reach an entire community. Also don’t forget to look for an
existing issue before opening a new one.

Lastly, If you are planning to open an issue on GitHub, please don’t forget to tell us the
version of your libcoraza and the version of the nginx connector you are running.

### Security issue

Please do not publicly report any security issue. Instead, contact us at:
security@coraza.io to report the issue. Once the problem is fixed we will provide you with credit for the discovery.


## Feature Request

We would love to discuss any ideas that you may have for a new feature. Please keep in mind this is a community driven project so be sure to contact the community via the mailing list to get feedback first. Alternatively,
feel free to open GitHub issues requesting for new features. Before opening a new issue, please check if there is an existing feature request for the desired functionality.


## Packaging

Having our packages in distros on time is something we highly desire. Let us know if
there is anything we can do to facilitate your work as a packager.


