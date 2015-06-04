#include "ngx_shm_dict_view.h"
#include "ngx_shm_dict_handler.h"


static char* ngx_http_shm_dict_view(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);



static ngx_command_t  ngx_http_shm_dict_view_commands[] = {

    { ngx_string("ngx_shm_dict_view"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_shm_dict_view,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

};
 
static ngx_http_module_t  ngx_http_shm_dict_view_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,   				        /* postconfiguration */

    NULL, /* create main configuration */
    NULL,  /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    NULL,  /* create location configuration */
    NULL /* merge location configuration */
};


ngx_module_t  ngx_http_shm_dict_view_module = {
    NGX_MODULE_V1,
    &ngx_http_shm_dict_view_module_ctx, /* module context */
    ngx_http_shm_dict_view_commands,   /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,   /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,      /* exit process */
    NULL,      /* exit master */
    NGX_MODULE_V1_PADDING
};



ngx_chain_t* 
ngx_http_shm_dict_resp(ngx_http_request_t *r, const char* output, int size){
	ngx_chain_t* chain = ngx_alloc_chain_link(r->pool);
	if(chain == NULL){
		ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"[ngx_shm_dict_view] failed to allocate response chain");
		return NULL;
	}
	
    u_char* buf = (u_char*)ngx_pcalloc(r->pool, size);
	if(buf == NULL){
		ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"[ngx_shm_dict_view] failed to allocate response buffer");
        return NULL;
	}
	ngx_memcpy(buf, output, size);
	
    ngx_buf_t    *b;
    b = (ngx_buf_t*)ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
		ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"[ngx_shm_dict_view] failed to allocate response buffer");
        return NULL;
    }
    b->memory = 1;
    b->last_buf = 1;

    chain->buf = b;
    chain->next = NULL;
    b->pos = (u_char*)buf;
    b->last = (u_char*)(b->pos+size);

	return chain;

}


ngx_int_t 
ngx_http_dict_view_set(ngx_http_request_t *r) {
	ngx_int_t rc = NGX_HTTP_OK;
	int32_t ikey = 0;
	ngx_str_t zone = ngx_null_string;
	ngx_str_t key = ngx_null_string;
	ngx_str_t value = ngx_null_string;
	
	if(ngx_http_arg(r, (u_char*)"zone", 4, &zone)!=NGX_OK){
		return NGX_HTTP_BAD_REQUEST;
	}

	u_char *zone_name;
    zone_name = (u_char *)ngx_pcalloc(r->pool, zone.len+1);
    if(zone_name == NULL) {
		ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"[ngx_shm_dict_view] failed to allocate zone_name");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
	ngx_sprintf(zone_name,"%V",&zone);
	zone.data = zone_name;
	
    if(ngx_http_arg(r, (u_char*)"key", 3, &key)!=NGX_OK){
		return NGX_HTTP_BAD_REQUEST;
	}

	if(ngx_http_arg(r, (u_char*)"value", 5, &value)!=NGX_OK){
		return NGX_HTTP_BAD_REQUEST;
	}

	//���key��ʼΪ0x ��ʾʹ�����ֵ�KEY.
	if(key.len > 2 && key.data[0] == '0' &&	key.data[1] == 'x'){
		key.data += 2;
		key.len -= 2;
		ikey = ngx_hextoi(key.data, key.len);
		ngx_str_handler_set_int32(&key, &ikey);
	}
	
	uint32_t exptime = 0;
	ngx_str_t sexptime = ngx_null_string;
	if(ngx_http_arg(r, (u_char*)"exptime", 7, &sexptime)==NGX_OK){
		exptime = ngx_parse_time(&sexptime, 1);
	}
	
	ngx_shm_zone_t *zone_t;
	zone_t = ngx_http_get_shm_zone(&zone);
    if ( zone_t == NULL ) {
		ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"[ngx_shm_dict_view] failed to get_shm_zone");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    } 

	rc = ngx_shm_dict_handler_set(zone_t,&key,&value,exptime);
	
	u_char* rsp = ngx_pcalloc(r->connection->pool, 1024+key.len+value.len);
	int rsp_len = 0;
	if(rc == 0){
		rsp_len = ngx_sprintf(rsp, "[ngx_shm_dict_view] process=[%d] operate=[set] zone=[%V] key=[%V] value=[%V] exptime=[%d] is success!\n",ngx_getpid(),&zone,&key,&value,(int)exptime)-rsp;
	}
	else{
		rsp_len = ngx_sprintf(rsp, "[ngx_shm_dict_view] process=[%d] operate=[set] zone=[%V] key=[%V] value=[%V] exptime=[%d] is failed!\n",ngx_getpid(),&zone,&key,&value,(int)exptime)-rsp;
	}

    r->headers_out.status = NGX_HTTP_OK;
	
    ngx_chain_t* chain = ngx_http_shm_dict_resp(r, (char *)rsp, rsp_len);
	if(chain != NULL){
	    r->headers_out.content_length_n = rsp_len;
	}
	else{
		r->headers_out.content_length_n = 0;
	}
	
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,"[ngx_shm_dict_view] %s",rsp);

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }else{
    	rc = ngx_http_output_filter(r, chain);
    }
	
	return rc;
}


ngx_int_t 
ngx_http_dict_view_get(ngx_http_request_t *r) {
	ngx_int_t rc = NGX_HTTP_OK;
	int32_t ikey = 0;
	ngx_str_t zone = ngx_null_string;
	ngx_str_t key = ngx_null_string;
	ngx_str_t value = ngx_null_string;
	uint32_t exptime = 0;
	
	if(ngx_http_arg(r, (u_char*)"zone", 4, &zone)!=NGX_OK){
		return NGX_HTTP_BAD_REQUEST;
	}
	
	u_char *zone_name;
    zone_name = (u_char *)ngx_pcalloc(r->pool, zone.len+1);
    if(zone_name == NULL) {
		ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"[ngx_shm_dict_view] failed to allocate zone_name");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
	ngx_sprintf(zone_name,"%V",&zone);
	zone.data = zone_name;
	
    if(ngx_http_arg(r, (u_char*)"key", 3, &key)!=NGX_OK){
		return NGX_HTTP_BAD_REQUEST;
	}
	
    if(key.len > 2 && key.data[0] == '0' &&	key.data[1] == 'x'){
		key.data += 2;
		key.len -= 2;
		ikey = ngx_hextoi(key.data, key.len);
		ngx_str_handler_set_int32(&key, &ikey);
	} 	
	
	ngx_shm_zone_t *zone_t;
	zone_t = ngx_http_get_shm_zone(&zone);
    if ( zone_t == NULL ) {
		ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"[ngx_shm_dict_view] failed to get_shm_zone");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    } 

	rc = ngx_shm_dict_handler_get(zone_t,&key,&value,&exptime);
	
	u_char* rsp = ngx_pcalloc(r->connection->pool, 1024+key.len+value.len);
	int rsp_len = 0;
	if(rc == 0){
		rsp_len = ngx_sprintf(rsp, "[ngx_shm_dict_view] process=[%d] operate=[get] zone=[%V] key=[%V] value=[%V] exptime=[%d] is success!\n",ngx_getpid(),&zone,&key,&value,exptime)-rsp;
	}
	else{
		rsp_len = ngx_sprintf(rsp, "[ngx_shm_dict_view] process=[%d] operate=[get] zone=[%V] key=[%V] value=[%V] exptime=[%d] is failed!\n",ngx_getpid(),&zone,&key,&value,exptime)-rsp;
	}

    r->headers_out.status = NGX_HTTP_OK;
	ngx_chain_t* chain = ngx_http_shm_dict_resp(r, (char *)rsp, rsp_len);
	if(chain != NULL){
	    r->headers_out.content_length_n = rsp_len;
	}
	else{
		r->headers_out.content_length_n = 0;
	}

	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,"[ngx_shm_dict_view] %s",rsp);
    
    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }else{
    	rc = ngx_http_output_filter(r, chain);
    }

	return rc;
}

ngx_int_t 
ngx_http_dict_view_del(ngx_http_request_t *r) {
	ngx_int_t rc = NGX_HTTP_OK;
	int32_t ikey = 0;
	ngx_str_t zone = ngx_null_string;
	ngx_str_t key = ngx_null_string;
	
	if(ngx_http_arg(r, (u_char*)"zone", 4, &zone)!=NGX_OK){
		return NGX_HTTP_BAD_REQUEST;
	}
	
	u_char *zone_name;
    zone_name = (u_char *)ngx_pcalloc(r->pool, zone.len+1);
    if(zone_name == NULL) {
		ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"[ngx_shm_dict_view] failed to allocate zone_name");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
	ngx_sprintf(zone_name,"%V",&zone);
	zone.data = zone_name;
	
	if(ngx_http_arg(r, (u_char*)"key", 3, &key)!=NGX_OK){
		return NGX_HTTP_BAD_REQUEST;
	}
	
    if(key.len > 2 && key.data[0] == '0' &&	key.data[1] == 'x'){
		key.data += 2;
		key.len -= 2;
		ikey = ngx_hextoi(key.data, key.len);
		ngx_str_handler_set_int32(&key, &ikey);
	} 	
	
	ngx_shm_zone_t *zone_t;
	zone_t = ngx_http_get_shm_zone(&zone);
    if ( zone_t == NULL ) {
		ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"[ngx_shm_dict_view] failed to get_shm_zone");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    } 

	rc = ngx_shm_dict_handler_delete(zone_t,&key);
	
	u_char* rsp = ngx_pcalloc(r->connection->pool, 1024+key.len);
	int rsp_len = 0;
	if(rc == 0){
		rsp_len = ngx_sprintf(rsp, "[ngx_shm_dict_view] oprocess=[%d] perate=[del] zone=[%V] key=[%V] is success!\n",ngx_getpid(),&zone,&key)-rsp;
	}
	else{
		rsp_len = ngx_sprintf(rsp, "[ngx_shm_dict_view] process=[%d] operate=[del] zone=[%V] key=[%V] is failed!\n",ngx_getpid(),&zone,&key)-rsp;
	}

    r->headers_out.status = NGX_HTTP_OK;
	
    ngx_chain_t* chain = ngx_http_shm_dict_resp(r, (char *)rsp, rsp_len);
	if(chain != NULL){
	    r->headers_out.content_length_n = rsp_len;
	}
	else{
		r->headers_out.content_length_n = 0;
	}

	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,"[ngx_shm_dict_view] %s",rsp);
    
    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }else{
    	rc = ngx_http_output_filter(r, chain);
    }
	
	return rc;
}

ngx_int_t
ngx_http_dict_view_incr(ngx_http_request_t *r) {
	ngx_int_t rc = NGX_HTTP_OK;
	ngx_str_t zone = ngx_null_string;
	ngx_str_t key = ngx_null_string;
	ngx_str_t szn = ngx_null_string;
	int32_t ikey = 0;
	ngx_int_t n = 1;
	int64_t cur = 0;
	
	if(ngx_http_arg(r, (u_char*)"zone", 4, &zone)!=NGX_OK){
		return NGX_HTTP_BAD_REQUEST;
	}
	
	u_char *zone_name;
    zone_name = (u_char *)ngx_pcalloc(r->pool, zone.len+1);
    if(zone_name == NULL) {
		ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"[ngx_shm_dict_view] failed to allocate zone_name");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
	ngx_sprintf(zone_name,"%V",&zone);
	zone.data = zone_name;
	
	if(ngx_http_arg(r, (u_char*)"key", 3, &key)!=NGX_OK){
		return NGX_HTTP_BAD_REQUEST;
	}
	
    if(key.len > 2 && key.data[0] == '0' &&	key.data[1] == 'x'){
		key.data += 2;
		key.len -= 2;
		ikey = ngx_hextoi(key.data, key.len);
		ngx_str_handler_set_int32(&key, &ikey);
	}

	if(ngx_http_arg(r, (u_char*)"n", 1, &szn)==NGX_OK){
		n = ngx_atoi(szn.data, szn.len);
	}
	
	ngx_shm_zone_t *zone_t;
	zone_t = ngx_http_get_shm_zone(&zone);
    if ( zone_t == NULL ) {
		ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"[ngx_shm_dict_view] failed to get_shm_zone");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    } 

	rc = ngx_shm_dict_handler_incr_int(zone_t,&key,n,0,&cur);
	
	u_char* rsp = ngx_pcalloc(r->connection->pool, 1024+key.len);
	int rsp_len = 0;
	
	if(rc == 0){
		rsp_len = ngx_sprintf(rsp, "[ngx_shm_dict_view] process=[%d] operate=[incr] zone=[%V] key=[%V] n=[%d] result=[%d] is success!\n",ngx_getpid(),&zone, &key,(int)n,(int)cur)-rsp;
    }else{
		rsp_len = ngx_sprintf(rsp, "[ngx_shm_dict_view] process=[%d] operate=[incr] zone=[%V] key=[%V] n=[%d] result=[%d] is failed!\n",ngx_getpid(),&zone, &key,(int)n,(int)cur)-rsp;
	}

    r->headers_out.status = NGX_HTTP_OK;
	ngx_chain_t* chain = ngx_http_shm_dict_resp(r, (char *)rsp, rsp_len);
	if(chain != NULL){
	    r->headers_out.content_length_n = rsp_len;
	}
	else{
		r->headers_out.content_length_n = 0;
	}
	
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,"[ngx_shm_dict_view] %s",rsp);

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }else{
    	rc = ngx_http_output_filter(r, chain);
    }

	return rc;
}

static ngx_int_t 
ngx_http_shm_dict_view_handler(ngx_http_request_t *r)
{
	//ngx_int_t rc;
	ngx_shm_r = r;

    u_char *uri;
    uri = (u_char *)ngx_pcalloc(r->pool, r->uri.len+1);
    if (uri == NULL) {
		ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"[ngx_shm_dict_view] failed to allocate uri");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_sprintf(uri, "%V", &r->uri);

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,"[ngx_shm_dict_view] uri %s",uri);

    if( ngx_strcmp(uri,"/get") == 0 ) {
        return ngx_http_dict_view_get(r);
    }
    
	if( ngx_strcmp(uri,"/set") == 0 ) {
        return ngx_http_dict_view_set(r);
    }
     
	if( ngx_strcmp(uri,"/del") == 0 ) {
        return ngx_http_dict_view_del(r);
    }
    
	if( ngx_strcmp(uri,"/incr") == 0 ) {
        return ngx_http_dict_view_incr(r);
    }

    return NGX_HTTP_NOT_FOUND;
}

static char * 
ngx_http_shm_dict_view(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{	
    ngx_http_core_loc_conf_t  *clcf;

    clcf = (ngx_http_core_loc_conf_t*)ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_shm_dict_view_handler;
	
    return NGX_CONF_OK;
}
