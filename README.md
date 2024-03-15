# Nginx external headers checker module

## nginx-external-headers-checker-module
This module is a fork of standard nginx-auth-request-module, but with some operational changes.

By default nginx-auth-request-module doesn't attach request args to subrequest and operate only with auth header.
This module corrects this feature and helps check many request args in one subrequest.

After success subrequest module helps set some extended headers which external system cannot see, but upstream can.
After unsuccess subrequest you can choose nginx response action.
Standard responses is 400,401,403,502,503 but you can use response 444 for immediately close incoming connection.
Response 444 can be used for ddos protection for you system, because you can drop incoming connection without resource utilisation.

## nginx-external-headers-checker-module-pftabled
This module is extended version of nginx-external-headers-checker-module.

Module contains pftabled notification mechanism used in *BSD systems.
After unsuccessful subrequest with status 444 you can choose packet filter table name and server which controls your incoming traffic.
This options helps ban external requests from harmful addresses and slows down theirs activity.

## Usage for STS(Secure Token Service) conversion (User Cookie -> App Bearer)
```
load_module modules/ngx_http_external_headers_checker_module.so;
http {
  server {
      location /protected {
          external_headers_checker  @sts_converter;
          external_headers_checker_set $xbearer $upstream_http_x_access_token; # set internal variable with token for upstream
      
          # ----- Fix cookie result -----
          external_headers_checker_set $xcookie $upstream_http_set_cookie; # set internal variable with cookie set/reset data for client
          add_header Set-Cookie $xcookie always; # set cookie header in response
          # ----- Fix cookie result -----
      
          proxy_set_header Authorization "Bearer $xbearer"; # set Bearer with data from external checker for upstream request
          proxy_set_header Cookie ""; # Drop current cookie data from upstream request
          proxy_set_header Host $host;
          proxy_set_header X-Real-IP $remote_addr;
          proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      
          proxy_hide_header "X-Access-Token";
          proxy_hide_header "Authorization";
          proxy_hide_header "Cookie";
          proxy_hide_header Access-Control-Allow-Origin;
          proxy_hide_header Access-Control-Allow-Headers;
          proxy_hide_header Access-Control-Allow-Credentials;
          proxy_hide_header Access-Control-Allow-Methods;
      
          resolver 127.0.0.11 valid=10s ipv6=off;
          proxy_pass http://protected_data_upstream;
      }
      
      location = @sts_converter {
          access_log /var/log/nginx/external_headers_checker.internal.log internal;
          internal;
          set $auth_uri $http_x_auth_uri;
          proxy_http_version 1.1;
          proxy_pass_request_body off;
          proxy_set_header Content-Length "";
          proxy_set_header Connection "";
          proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
          proxy_set_header X-Forwarded-Proto $scheme;
          proxy_set_header Content-Length "";
          proxy_set_header X-Original-URI $request_uri;
          proxy_set_header X-Original-ARGS $args;
          proxy_set_header X-Remote-Addr $remote_addr;
          proxy_set_header X-Original-Host $host;
          proxy_pass http://external_checker_upstream;
      }
  }
}
```
## Usage for pftabled blocking notification

For ban harmful address in pf, set four headers in response from external checker
```
X-Block-Source-Address = <harmful IP address>
X-Block-Table = <pf table name>
X-Block-Target-Server = <pftabled location>
X-Block-Target-Server-Port = <pftabled port>
```
Set parameters
```
load_module modules/ngx_http_external_headers_checker_module_pftabled.so;
main {
  pftabled_sha_keyfile /etc/pftabled.key;
}
http {
  server {    

    location / {
        root   /usr/share/nginx/html;
        index  index.html index.htm;
    }

   location /protected {
        external_headers_checker  @external_headers_checker;
        external_headers_checker_set $xout $upstream_http_x_block_table;
        set $x_block_table $upstream_http_x_block_table;
        add_header X-Block-Table $x_block_table;
        proxy_pass http://resource_upstream;
    }

    location = @external_headers_checker {
        internal;

        set $auth_uri $http_x_auth_uri;
        proxy_http_version 1.1;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-ARGS $args;
        proxy_set_header X-Remote-Addr $remote_addr;
        proxy_set_header X-Original-Host $host;
        proxy_pass "http://checker_upstream";
    }
  }
}
```
## Build module

### Build Ubuntu deb package with dpkg-buildpackage

### Build Nginx docker image with module


