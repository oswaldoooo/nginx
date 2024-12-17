#include "base64.h"
#include "ngx_conf_file.h"
#include "ngx_config.h"
#include "ngx_palloc.h"
#include "ngx_string.h"
#include "ngx_times.h"
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <string.h>
#include <sys/types.h>
typedef struct {
  ngx_flag_t enable;
  ngx_str_t public_key;
} anti_leech_loc_conf_t;
ngx_command_t anti_leech_commands[] = {
    {
        ngx_string("anti-leech"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(anti_leech_loc_conf_t, enable),
        NULL,
    },
    {
        ngx_string("anti-leech-public-key"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(anti_leech_loc_conf_t, public_key),
        NULL,
    },
    ngx_null_command,
};
ngx_int_t access_handler(ngx_http_request_t *req);
ngx_int_t anti_leech_init(ngx_conf_t *conf);
//验证签名
ngx_uint_t verify_anti_leech_sign(ngx_str_t *sign, ngx_str_t *msg,
                                  EVP_PKEY *anti_leech_pkey) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, anti_leech_pkey);
  int ok = EVP_DigestVerify(mdctx, sign->data, sign->len, msg->data, msg->len);
  EVP_MD_CTX_free(mdctx);
  return ok;
}
//

void *create_loc_conf(ngx_conf_t *conf) {
  anti_leech_loc_conf_t *data =
      ngx_pnalloc(conf->pool, sizeof(anti_leech_loc_conf_t));
  if (data == NULL) {
    return NULL;
  }
  ngx_log_error(NGX_LOG_ERR, conf->log, 0, "create local conf");
  data->enable = NGX_CONF_UNSET;
  return data;
}
char *merge_loc_conf(ngx_conf_t *conf, void *pre, void *now) {
  anti_leech_loc_conf_t *last = pre;
  anti_leech_loc_conf_t *latest = now;
  ngx_conf_merge_value(last->enable, latest->enable, 0);
  ngx_log_error(NGX_LOG_ERR, conf->log, 0,
                "merge conf finished old->enable=%d latest->enable=%d ",
                last->enable, latest->enable);
  return NGX_CONF_OK;
}
ngx_http_module_t ngx_http_anti_leech_module_ctx = {
    NULL, anti_leech_init, NULL,           NULL, NULL,
    NULL, create_loc_conf, merge_loc_conf,
};
ngx_module_t ngx_http_anti_leech_module = {
    NGX_MODULE_V1,
    &ngx_http_anti_leech_module_ctx,
    anti_leech_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING,
};
// base64 url编码转标砖编码
void url_encode_to_std_encode(u_char *data, size_t data_len) {
  char *next = ngx_strstr(data, "-");
  while (next) {
    next[0] = '+';
    next = ngx_strstr(next, "-");
  }
  next = ngx_strstr(data, "_");
  while (next) {
    next[0] = '/';
    next = ngx_strstr(next, "_");
  }
  next = ngx_strstr(data, "%3D");
  // u_char *end = data + data_len;
  size_t count = 0;
  while (next) {
    // size_t dis = end - (u_char *)next - 3;
    next[0] = 0;
    next[1] = 0;
    next[2] = 0;
    count++;
    next = ngx_strstr(next, "%3D");
  }
  if (count) {
    next = (char *)(data + (data_len - count * 3));
    for (size_t i = 0; i < count; i++) {
      next[0] = '=';
      next++;
    }
  }
}

ngx_int_t access_handler(ngx_http_request_t *req) {
  anti_leech_loc_conf_t *conf =
      ngx_http_get_module_loc_conf(req, ngx_http_anti_leech_module);
  if (conf->enable != 1) { //不需要防盗链
    ngx_http_core_loc_conf_t *clcf =
        ngx_http_get_module_loc_conf(req, ngx_http_core_module);
    clcf->satisfy = NGX_HTTP_SATISFY_ALL;
    return NGX_OK;
  }
  if (conf->public_key.len == 0) { //没有配置公钥
    ngx_log_error(NGX_LOG_ERR, req->connection->log, 0,
                  "not config public key");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  ngx_str_t name = ngx_string("arg_sign");
  ngx_http_variable_value_t *sign_value =
      ngx_http_get_variable(req, &name, ngx_hash_key(name.data, name.len));
  if (sign_value == NULL || sign_value->not_found) {
    ngx_log_error(NGX_LOG_INFO, req->connection->log, 0,
                  "value is NULL %d not found= %d", sign_value == NULL,
                  sign_value->not_found);
    return NGX_HTTP_NOT_FOUND;
  }
  u_char *unescape_uri = ngx_palloc(req->pool, sign_value->len);
  u_char *unescape_uri_start = unescape_uri;
  ngx_unescape_uri(&unescape_uri, &sign_value->data, sign_value->len, 0);
  size_t decode_len = unescape_uri - unescape_uri_start;
  url_encode_to_std_encode(unescape_uri_start, decode_len);
  size_t decode_size = BASE64_DECODE_OUT_SIZE(decode_len);
  u_char temp_buff[decode_size];
  temp_buff[decode_size - 1] = 0;
  int real_size =
      base64_decode((char *)unescape_uri_start, decode_len, temp_buff);
  if (real_size <= 0) {
    ngx_str_t temp_sign = {.data = unescape_uri_start, .len = decode_len};
    ngx_log_error(NGX_LOG_INFO, req->connection->log, 0,
                  "decode sign message failed not base64 encode %V real size "
                  "%d decode size %d",
                  &temp_sign, real_size, decode_size);
    return NGX_HTTP_NOT_FOUND;
  }
  for (size_t i = (size_t)real_size; i < decode_size; i++) {
    temp_buff[i] = 0;
  }
  ngx_str_t sign_msg = {.data = temp_buff, .len = (size_t)real_size};
  ngx_str_t time = ngx_string("arg_time");
  ngx_http_variable_value_t *time_value =
      ngx_http_get_variable(req, &time, ngx_hash_key(time.data, time.len));
  if (time_value == NULL || time_value->not_found) {
    ngx_log_error(NGX_LOG_ERR, req->connection->log, 0,
                  "value is NULL %d not found= %d", sign_value == NULL,
                  sign_value->not_found);
    return NGX_HTTP_NOT_FOUND;
  }
  ngx_int_t _time = ngx_atoi(time_value->data, time_value->len);
  ngx_int_t now = ngx_time();
  if (_time <= now) {
    ngx_log_error(NGX_LOG_INFO,req->connection->log,0,"anti leech time is expired");
    return NGX_HTTP_NOT_FOUND;
  }
  ngx_str_t uri = req->uri;
  size_t val_len = uri.len + time_value->len;
  u_char *val = ngx_pnalloc(req->pool, val_len + 1);
  if (val == NULL) {
    ngx_log_error(NGX_LOG_ERR, req->connection->log, 0,
                  "ngx pnalloc memory failed");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }
  ngx_str_t time_s = {.data = time_value->data, .len = time_value->len};
  ngx_snprintf(val, val_len + 1, "%V%V", &uri, &time_s);
  val[val_len] = 0;
  ngx_str_t real_val = {.data = val, .len = val_len};
  decode_size = BASE64_DECODE_OUT_SIZE(conf->public_key.len);
  if (decode_size != 33) {
    ngx_log_error(NGX_LOG_ERR, req->connection->log, 0,
                  "anti leech config error. publickey %V is not base64 encode "
                  "decode size %d",
                  &conf->public_key, decode_size);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }
  u_char *pkey_decode = ngx_palloc(req->pool, decode_size);
  real_size = base64_decode((char *)conf->public_key.data, conf->public_key.len,
                            pkey_decode);
  if ((size_t)real_size != 32) {
    ngx_log_error(
        NGX_LOG_ERR, req->connection->log, 0,
        "anti leech public key has problem. base64 decode failed real size %d",
        real_size);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }
  EVP_PKEY *pkey_evp =
      EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pkey_decode, 32);
  if (!pkey_evp) {
    ngx_log_error(NGX_LOG_ERR, req->connection->log, 0,
                  "new raw evp pkey public key failed");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }
  if (!verify_anti_leech_sign(&sign_msg, &real_val, pkey_evp)) {
    u_char buf[1024] = {0}; // 假设最大输出 1024 字节
    u_char *p = buf;

    for (size_t i = 0; i < sign_msg.len; i++) {
      p = ngx_snprintf(p, buf + sizeof(buf) - p, "%d ",
                       sign_msg.data[i]); // 格式化输出每个字节
    }
    ngx_log_error(NGX_LOG_INFO, req->connection->log, 0,
                  "anti leech verify failed [%s]", buf);
    return NGX_HTTP_NOT_FOUND;
  }

  ngx_http_core_loc_conf_t *clcf =
      ngx_http_get_module_loc_conf(req, ngx_http_core_module);
  clcf->satisfy = NGX_HTTP_SATISFY_ALL;
  return NGX_OK;
}
ngx_int_t anti_leech_init(ngx_conf_t *conf) {
  anti_leech_loc_conf_t *lcnf =
      ngx_http_conf_get_module_loc_conf(conf, ngx_http_anti_leech_module);
  ngx_log_error(NGX_LOG_ERR, conf->log, 0, "anti leech enable %d pubkey len %d",
                lcnf->enable);
  ngx_http_core_main_conf_t *cnf =
      ngx_http_conf_get_module_main_conf(conf, ngx_http_core_module);
  if (cnf == NULL) {
    ngx_log_error(NGX_LOG_ERR, conf->log, 0, "get module main conf failed");
    return NGX_ERROR;
  }

  ngx_http_handler_pt *h;
  h = ngx_array_push(&cnf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
  if (h == NULL) {
    ngx_log_error(NGX_LOG_ERR, conf->log, 0,
                  "array push http access phase failed");
    return NGX_ERROR;
  } else {
    (*h) = access_handler;
  }
  return NGX_OK;
}