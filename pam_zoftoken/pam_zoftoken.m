//
//  pam_zoftoken
//
//  Created by Juan Colo on 6/1/20.
//  Copyright © 2020 Hamza Sood. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <syslog.h>
#include <curl/curl.h>

struct curl_fetch_st {
    char *payload;
    size_t size;
};

struct options_t {
    int debug;
    char *service;
    char *no_2fa_user;
    char *auth_key;
    char *host;
    char *user;
};
typedef struct options_t options_t;

static inline const char *
pam_str_skip_prefix_len(const char *str, const char *prefix, size_t prefix_len)
{
    return strncmp(str, prefix, prefix_len) ? NULL : str + prefix_len;
}

#define pam_str_skip_prefix(str_, prefix_)    \
    pam_str_skip_prefix_len((str_), (prefix_), sizeof(prefix_) - 1)


// Ignore requests for the stuff we don't support
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_IGNORE; }
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)   { return PAM_IGNORE; }
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_IGNORE; }

/* callback for curl fetch */
size_t curl_callback (void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct curl_fetch_st *p = (struct curl_fetch_st *) userp;
    
    /* expand buffer */
    p->payload = (char *) realloc(p->payload, p->size + realsize + 1);

    /* check buffer */
    if (p->payload == NULL) {
      /* this isn't good */
      
      syslog(LOG_ERR, "ERROR: Failed to expand buffer in curl_callback");
      /* free buffer */
      free(p->payload);
      /* return */
      return PAM_AUTH_ERR;
    }

    /* copy contents to buffer */
    memcpy(&(p->payload[p->size]), contents, realsize);

    /* set new buffer size */
    p->size += realsize;

    /* ensure null termination */
    p->payload[p->size] = 0;

    /* return size */
    return realsize;
}

/* fetch and return url body via curl */
CURLcode curl_fetch_url(CURL *ch, const char *url, struct curl_fetch_st *fetch) {
    CURLcode rcode;                   /* curl result code */

    /* init payload */
    fetch->payload = (char *) calloc(1, sizeof(fetch->payload));

    /* check payload */
    if (fetch->payload == NULL) {
        /* log error */
        fprintf(stderr, "ERROR: Failed to allocate payload in curl_fetch_url");
        /* return error */
        return CURLE_FAILED_INIT;
    }

    /* init size */
    fetch->size = 0;

    /* set url to fetch */
    curl_easy_setopt(ch, CURLOPT_URL, url);
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, curl_callback);
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void *) fetch);
    curl_easy_setopt(ch, CURLOPT_USERAGENT, "libcurl-agent/1.0");
    curl_easy_setopt(ch, CURLOPT_TIMEOUT, 15);
    curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(ch, CURLOPT_MAXREDIRS, 1);

    /* fetch the url */
    rcode = curl_easy_perform(ch);

    return rcode;
}

void parse_option (const char *argv, options_t *options)
{
    const char *str;
    if ((str = pam_str_skip_prefix(argv, "service=")) != NULL)  {
        options->service  = (char *) calloc(1, sizeof(str));
        strcpy(options->service, str);
    }
    else if ((str = pam_str_skip_prefix(argv, "no_2fa_user=")) != NULL) {
           options->no_2fa_user  = (char *) calloc(1, sizeof(str));
        strcpy(options->no_2fa_user, str);
    }
    else if ((str = pam_str_skip_prefix(argv, "auth_key=")) != NULL) {
        options->auth_key  = (char *) calloc(1, sizeof(str));
        strcpy(options->auth_key, str);
    }
    else if ((str = pam_str_skip_prefix(argv, "host=")) != NULL) {
        options->host  = (char *) calloc(1, sizeof(str));
        strcpy(options->host, str);
    }
//        syslog(LOG_ERR, "pam_zoftoken: OPTS: %s", str);
//    else if (strcasecmp (argv, "debug") == 0)
       // options->debug = 1;
//    else
//        syslog(LOG_ERR, "pam_zoftoken: unknown option: %s", argv);

    syslog(LOG_ERR, "pam_zoftoken service: %s", options->service);
}

void create_url(options_t *options, char *dest) {
        
    char protocol[] = "https://";
    char path[] = "/token/status?";
    char var_user[] = "id=";
    char var_service[] = "&service=";
    char var_auth_key[] = "&authKey=";
    
    strcat(dest, protocol);
    strcat(dest, options->host);
    strcat(dest, path);
    strcat(dest, var_user);
    strcat(dest, options->user);
    strcat(dest, var_service);
    strcat(dest, options->service);
    strcat(dest, var_auth_key);
    strcat(dest, options->auth_key);
    
    syslog(LOG_ERR, "pam_zoftoken - URL: %s" ,dest);
}


PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    
    options_t options;
    memset (&options, 0, sizeof (options));
    
    /* Parse parameters for module */
    for ( ; argc-- > 0; argv++)
       parse_option (*argv, &options);
    
    const char *user;
    pam_get_user(pamh, &user, NULL);
    options.user = (char *)malloc(sizeof(user));
    strcpy(options.user, user);
    
    /* no 2 fa user*/
    if (strcasecmp (options.user, options.no_2fa_user) == 0) {
        free(options.auth_key);
        free(options.service);
        free(options.host);
        free(options.no_2fa_user);
        free(options.user);
        
        return PAM_SUCCESS;
    }
    
//    char *dest = (char *) malloc(
//    43 +
//    sizeof(options.host) +
//    sizeof(options.user) +
//    sizeof(options.service) +
//    sizeof(options.auth_key));
    char *url = (char *) malloc(1024);
    
    create_url(&options, url);
    printf("ZOFTOKEN URL:   %s",  url);
    
    CURL *ch;
    CURLcode rcode;

    struct curl_fetch_st curl_fetch;
    struct curl_fetch_st *cf = &curl_fetch;
    struct curl_slist *headers = NULL;
    
    if ((ch = curl_easy_init()) == NULL) {
        syslog(LOG_ERR, "%s", "ERROR: Failed to create curl handle in fetch_session");
        return PAM_AUTH_ERR;
    }

    /* set content type */
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* set curl options */
    curl_easy_setopt(ch, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);

    rcode = curl_fetch_url(ch, url, cf);
    
    /* cleanup curl handle */
    curl_easy_cleanup(ch);

    /* free headers */
    curl_slist_free_all(headers);
    
    free(url);
    free(options.auth_key);
    free(options.service);
    free(options.host);
    free(options.no_2fa_user);
    free(options.user);

    /* check return code */
    if (rcode != CURLE_OK || cf->size < 1) {
        syslog(LOG_ERR, "ERROR: Failed to fetch url (%s) - curl said: %s", url, curl_easy_strerror(rcode));
        return PAM_AUTH_ERR;
    }

    /* check payload */
    if (cf->payload != NULL) {
        syslog(LOG_ERR, "CURL Returned: \n%s\n", cf->payload);
        
        int result = PAM_AUTH_ERR;
        
        if(strchr(cf->payload, '1') != NULL) {
            result = PAM_SUCCESS;
        } else {
            char *outmsj = "Your ZofToken is currently closed - access to this account is denied";
            pam_info(pamh, "%s", outmsj);
        }
        
        free(cf->payload);
        return result;
    } else {
        syslog(LOG_ERR,"ERROR: Failed to populate payload");
        free(cf->payload);
        return PAM_AUTH_ERR;
    }
}
