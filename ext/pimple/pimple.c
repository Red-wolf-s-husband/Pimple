
/*
 * This file is part of Pimple.
 *
 * Copyright (c) 2014 Fabien Potencier
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_pimple.h"
#include "pimple_compat.h"
#include "zend_interfaces.h"
#include "zend.h"
#include "Zend/zend_closures.h"
#include "ext/spl/spl_exceptions.h"
#include "Zend/zend_exceptions.h"
#include "main/php_output.h"
#include "SAPI.h"

static zend_class_entry *pimple_ce;
static zend_object_handlers pimple_object_handlers;
static zend_class_entry *pimple_closure_ce;
static zend_class_entry *pimple_serviceprovider_ce;
static zend_object_handlers pimple_closure_object_handlers;
static zend_internal_function pimple_closure_invoker_function;

static inline void pimple_object_handle_inheritance_object_handlers(zend_class_entry *ce TSRMLS_DC)
{
	zend_function *function    = NULL;

	if (ce != pimple_ce) {
		function = (zend_function *) zend_hash_str_find_ptr(&ce->function_table, ZEND_STRL("offsetget"));
		if (function->common.scope != ce) {
			pimple_object_handlers.read_dimension = pimple_object_read_dimension;
		}
		function = (zend_function *) zend_hash_str_find_ptr(&ce->function_table, ZEND_STRL("offsetset"));
		if (function->common.scope != ce) {
			pimple_object_handlers.write_dimension = pimple_object_write_dimension;
		}
		function = (zend_function *) zend_hash_str_find_ptr(&ce->function_table, ZEND_STRL("offsetexists"));
		if (function->common.scope != ce) {
			pimple_object_handlers.has_dimension = pimple_object_has_dimension;
		}
		function = (zend_function *) zend_hash_str_find_ptr(&ce->function_table, ZEND_STRL("offsetunset"));
		if (function->common.scope != ce) {
			pimple_object_handlers.unset_dimension = pimple_object_unset_dimension;
		}
	} else {
		pimple_object_handlers.read_dimension = pimple_object_read_dimension;
		pimple_object_handlers.write_dimension = pimple_object_write_dimension;
		pimple_object_handlers.has_dimension = pimple_object_has_dimension;
		pimple_object_handlers.unset_dimension = pimple_object_unset_dimension;
	}
}

static inline zval *pimple_call_cb(zval *object, pimple_bucket_value *retval, zval *rv TSRMLS_DC)
{
	zend_fcall_info fci = {0};

	Z_TRY_ADDREF_P(object);

	fci.size = sizeof(fci);
	fci.object = retval->fcc.object;
	fci.function_name  = retval->value;
	fci.no_separation  = 1;
	fci.retval = rv;
	fci.params = object;
	fci.param_count = 1;

	zend_call_function(&fci, &retval->fcc TSRMLS_CC);

	/* if (EG(exception)) {
		return NULL;
	} */
	return rv;
}

ZEND_BEGIN_ARG_INFO_EX(arginfo___construct, 0, 0, 0)
ZEND_ARG_ARRAY_INFO(0, value, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_offsetset, 0, 0, 2)
ZEND_ARG_INFO(0, offset)
ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_offsetget, 0, 0, 1)
ZEND_ARG_INFO(0, offset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_offsetexists, 0, 0, 1)
ZEND_ARG_INFO(0, offset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_offsetunset, 0, 0, 1)
ZEND_ARG_INFO(0, offset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_factory, 0, 0, 1)
ZEND_ARG_INFO(0, callable)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_protect, 0, 0, 1)
ZEND_ARG_INFO(0, callable)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_raw, 0, 0, 1)
ZEND_ARG_INFO(0, id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_extend, 0, 0, 2)
ZEND_ARG_INFO(0, id)
ZEND_ARG_INFO(0, callable)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_keys, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_register, 0, 0, 1)
ZEND_ARG_OBJ_INFO(0, provider, Pimple\\ServiceProviderInterface, 0)
ZEND_ARG_ARRAY_INFO(0, values, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_serviceprovider_register, 0, 0, 1)
ZEND_ARG_OBJ_INFO(0, pimple, Pimple\\Container, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry pimple_ce_functions[] = {
	PHP_ME(Pimple, __construct,	arginfo___construct, ZEND_ACC_PUBLIC)
	PHP_ME(Pimple, factory,         arginfo_factory,         ZEND_ACC_PUBLIC)
	PHP_ME(Pimple, protect,         arginfo_protect,         ZEND_ACC_PUBLIC)
	PHP_ME(Pimple, raw,             arginfo_raw,             ZEND_ACC_PUBLIC)
	PHP_ME(Pimple, extend,          arginfo_extend,          ZEND_ACC_PUBLIC)
	PHP_ME(Pimple, keys,            arginfo_keys,            ZEND_ACC_PUBLIC)
	PHP_ME(Pimple, register,		arginfo_register,		 ZEND_ACC_PUBLIC)

	PHP_ME(Pimple, offsetSet,       arginfo_offsetset,       ZEND_ACC_PUBLIC)
	PHP_ME(Pimple, offsetGet,       arginfo_offsetget,       ZEND_ACC_PUBLIC)
	PHP_ME(Pimple, offsetExists,    arginfo_offsetexists,    ZEND_ACC_PUBLIC)
	PHP_ME(Pimple, offsetUnset,     arginfo_offsetunset,     ZEND_ACC_PUBLIC)
	PHP_FE_END
};

static const zend_function_entry pimple_serviceprovider_iface_ce_functions[] = {
	PHP_ABSTRACT_ME(ServiceProviderInterface, register, arginfo_serviceprovider_register)
	PHP_FE_END
};

static inline pimple_closure_object *php_pimple_closure_fetch_object(zend_object *obj TSRMLS_DC){
	return (pimple_closure_object *)((char*)(obj) - XtOffsetOf(pimple_closure_object, zobj));
}

static inline pimple_object *php_pimple_fetch_object(zend_object *obj TSRMLS_DC){
	return (pimple_object *)((char*)(obj) - XtOffsetOf(pimple_object, zobj));
}

static inline pimple_object *z_pimple_p(zval * object TSRMLS_DC)
{
	return php_pimple_fetch_object(Z_OBJ_P(object) TSRMLS_CC);
}

static inline pimple_closure_object *z_pimple_closure_p(zval * object TSRMLS_DC)
{
	return php_pimple_closure_fetch_object(Z_OBJ_P(object) TSRMLS_CC);
}

static void pimple_closure_free_object_storage(zend_object *object TSRMLS_DC)
{
	pimple_closure_object *obj = php_pimple_closure_fetch_object(object TSRMLS_CC);
	zval_ptr_dtor(&obj->factory);
	zval_ptr_dtor(&obj->callable);
	zend_object_std_dtor(&obj->zobj TSRMLS_CC);
	// @todo this shouldn't be here, not sure why it's leaking
	efree(obj);
}

static void pimple_free_object_storage(zend_object *object TSRMLS_DC)
{
	pimple_object *obj = php_pimple_fetch_object(object TSRMLS_CC);
	zend_hash_destroy(&obj->factories);
	zend_hash_destroy(&obj->protected);
	zend_hash_destroy(&obj->values);
	zend_object_std_dtor(&obj->zobj TSRMLS_CC);
	// @todo this shouldn't be here, not sure why it's leaking
	efree(obj);
}

static void pimple_free_bucket(pimple_bucket_value *bucket)
{
	;
}

static zend_object *pimple_closure_object_create(zend_class_entry *ce TSRMLS_DC)
{
	pimple_closure_object *pimple_closure_obj = NULL;

	pimple_closure_obj = ecalloc(1, sizeof(pimple_closure_object) + zend_object_properties_size(ce));
	zend_object_std_init(&pimple_closure_obj->zobj, ce TSRMLS_CC);
	object_properties_init(&(pimple_closure_obj->zobj), ce);

	pimple_closure_obj->zobj.handlers = &pimple_closure_object_handlers;

	return &pimple_closure_obj->zobj;
}

static zend_function *pimple_closure_get_constructor(zend_object *obj TSRMLS_DC)
{
	zend_error(E_ERROR, "Pimple\\ContainerClosure is an internal class and cannot be instantiated");

	return NULL;
}

static int pimple_closure_get_closure(zval *obj, zend_class_entry **ce_ptr, union _zend_function **fptr_ptr, zend_object **zobj_ptr TSRMLS_DC)
{
	// @todo
/*
	*zobj_ptr = obj;
	*ce_ptr   = Z_OBJCE_P(obj);
	*fptr_ptr = (zend_function *)&pimple_closure_invoker_function;
	return SUCCESS;
*/
	return FAILURE;
}

static zend_object *pimple_object_create(zend_class_entry *ce TSRMLS_DC)
{
	pimple_object *pimple_obj  = NULL;
	zend_function *function    = NULL;

	pimple_obj = ecalloc(1, sizeof(pimple_object) + zend_object_properties_size(ce));
	zend_object_std_init(&pimple_obj->zobj, ce TSRMLS_CC);
	object_properties_init(&(pimple_obj->zobj), ce);

	pimple_object_handle_inheritance_object_handlers(ce TSRMLS_CC);

	pimple_obj->zobj.handlers = &pimple_object_handlers;

	zend_hash_init(&pimple_obj->factories, PIMPLE_DEFAULT_ZVAL_CACHE_NUM, NULL, (dtor_func_t)pimple_bucket_dtor, 0);
	zend_hash_init(&pimple_obj->protected, PIMPLE_DEFAULT_ZVAL_CACHE_NUM, NULL, (dtor_func_t)pimple_bucket_dtor, 0);
	zend_hash_init(&pimple_obj->values, PIMPLE_DEFAULT_ZVAL_VALUES_NUM, NULL, (dtor_func_t)pimple_bucket_dtor, 0);

	return &pimple_obj->zobj;
}

static void pimple_object_write_dimension(zval *object, zval *offset, zval *value TSRMLS_DC)
{
	pimple_object *pimple_obj = NULL;
	ulong index;
	pimple_obj = z_pimple_p(object TSRMLS_CC);

	pimple_bucket_value pimple_value = {0};
	pimple_bucket_value *found_value = NULL;

	pimple_zval_to_pimpleval(value, &pimple_value TSRMLS_CC);

	if (!offset) {/* $p[] = 'foo' when not overloaded */
		zend_hash_next_index_insert_mem(&pimple_obj->values, (void *)&pimple_value, sizeof(pimple_bucket_value));
		Z_TRY_ADDREF_P(value);
		return;
	}

	switch (Z_TYPE_P(offset)) {
	case IS_STRING:
		found_value = zend_hash_find_ptr(&pimple_obj->values, Z_STR_P(offset));
		if (found_value && found_value->type == PIMPLE_IS_SERVICE && found_value->initialized == 1) {
			// @todo this is causing a double-free
			//pimple_free_bucket(&pimple_value);
			zend_throw_exception_ex(spl_ce_RuntimeException, 0 TSRMLS_CC, "Cannot override frozen service \"%s\".", Z_STRVAL_P(offset));
			return;
		}
		//if (zend_hash_str_update_mem(&pimple_obj->values, Z_STRVAL_P(offset), Z_STRLEN_P(offset)+1, (void *)&pimple_value, sizeof(pimple_bucket_value)) == NULL) {
		if (zend_hash_str_update_mem(&pimple_obj->values, Z_STRVAL_P(offset), Z_STRLEN_P(offset), (void *)&pimple_value, sizeof(pimple_bucket_value)) == NULL) {
			pimple_free_bucket(&pimple_value);
			return;
		}
		Z_TRY_ADDREF_P(value);
	break;
	case IS_DOUBLE:
	case IS_TRUE:
	case IS_FALSE:
	case IS_LONG:
		if (Z_TYPE_P(offset) == IS_DOUBLE) {
			index = (ulong)Z_DVAL_P(offset);
		} else {
			index = Z_LVAL_P(offset);
		}
		found_value = zend_hash_index_find_ptr(&pimple_obj->values, index);
		if (found_value && found_value->type == PIMPLE_IS_SERVICE && found_value->initialized == 1) {
			pimple_free_bucket(&pimple_value);
			zend_throw_exception_ex(spl_ce_RuntimeException, 0 TSRMLS_CC, "Cannot override frozen service \"%ld\".", index);
			return;
		}
		if (zend_hash_index_update_mem(&pimple_obj->values, index, (void *)&pimple_value, sizeof(pimple_bucket_value)) == NULL) {
			pimple_free_bucket(&pimple_value);
			return;
		}
		Z_TRY_ADDREF_P(value);
	break;
	case IS_NULL: /* $p[] = 'foo' when overloaded */
		zend_hash_next_index_insert_mem(&pimple_obj->values, (void *)&pimple_value, sizeof(pimple_bucket_value));
		Z_TRY_ADDREF_P(value);
	break;
	default:
		pimple_free_bucket(&pimple_value);
		zend_error(E_WARNING, "Unsupported offset type");
	}
}

static void pimple_object_unset_dimension(zval *object, zval *offset TSRMLS_DC)
{
	pimple_object *pimple_obj = NULL;
	ulong index;
	pimple_obj = z_pimple_p(object TSRMLS_CC);

	switch (Z_TYPE_P(offset)) {
	case IS_STRING:
		zend_symtable_str_del(&pimple_obj->values, Z_STRVAL_P(offset), Z_STRLEN_P(offset));
		zend_symtable_str_del(&pimple_obj->factories, Z_STRVAL_P(offset), Z_STRLEN_P(offset));
		zend_symtable_str_del(&pimple_obj->protected, Z_STRVAL_P(offset), Z_STRLEN_P(offset));
	break;
	case IS_DOUBLE:
	case IS_TRUE:
	case IS_FALSE:
	case IS_LONG:
		if (Z_TYPE_P(offset) == IS_DOUBLE) {
			index = (ulong)Z_DVAL_P(offset);
		} else {
			index = Z_LVAL_P(offset);
		}
		zend_hash_index_del(&pimple_obj->values, index);
		zend_hash_index_del(&pimple_obj->factories, index);
		zend_hash_index_del(&pimple_obj->protected, index);
	break;
	default:
		zend_error(E_WARNING, "Unsupported offset type");
	}
}

static int pimple_object_has_dimension(zval *object, zval *offset, int check_empty TSRMLS_DC)
{
	pimple_object *pimple_obj = NULL;
	ulong index;
	pimple_obj = z_pimple_p(object TSRMLS_CC);

	pimple_bucket_value *retval = NULL;

	switch (Z_TYPE_P(offset)) {
	case IS_STRING:
		retval = zend_symtable_str_find_ptr(&pimple_obj->values, Z_STRVAL_P(offset), Z_STRLEN_P(offset));
		if (retval) {
			switch (check_empty) {
			case 0: /* isset */
				return 1; /* Differs from PHP behavior (Z_TYPE_P(retval->value) != IS_NULL;) */
			case 1: /* empty */
			default:
				return zend_is_true(&retval->value);
			}
		}
		return 0;
	break;
	case IS_DOUBLE:
	case IS_TRUE:
	case IS_FALSE:
	case IS_LONG:
		if (Z_TYPE_P(offset) == IS_DOUBLE) {
			index = (ulong)Z_DVAL_P(offset);
		} else {
			index = Z_LVAL_P(offset);
		}
		retval = zend_hash_index_find_ptr(&pimple_obj->values, index);
		if (retval) {
			switch (check_empty) {
				case 0: /* isset */
					return 1; /* Differs from PHP behavior (Z_TYPE_P(retval->value) != IS_NULL;)*/
				case 1: /* empty */
				default:
					return zend_is_true(&retval->value);
			}
		}
		return 0;
	break;
	default:
		zend_error(E_WARNING, "Unsupported offset type");
		return 0;
	}
}

static zval *pimple_object_read_dimension(zval *object, zval *offset, int type, zval *rv TSRMLS_DC)
{
	pimple_object *pimple_obj = NULL;
	ulong index;
	pimple_obj = z_pimple_p(object TSRMLS_CC);

	pimple_bucket_value *retval = NULL;
	zend_fcall_info fci = {0};
	zval cbrv = {0};

	switch (Z_TYPE_P(offset)) {
	case IS_STRING:
		retval = zend_symtable_str_find_ptr(&pimple_obj->values, Z_STRVAL_P(offset), Z_STRLEN_P(offset));
		if (!retval) {
			zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "Identifier \"%s\" is not defined.", Z_STRVAL_P(offset));
			return NULL;
		}
	break;
	case IS_DOUBLE:
	case IS_TRUE:
	case IS_FALSE:
	case IS_LONG:
		if (Z_TYPE_P(offset) == IS_DOUBLE) {
			index = (ulong)Z_DVAL_P(offset);
		} else {
			index = Z_LVAL_P(offset);
		}
		retval = zend_hash_index_find_ptr(&pimple_obj->values, index);
		if (!retval) {
			return NULL;
		}
	break;
	case IS_NULL: /* $p[][3] = 'foo' first dim access */
		return NULL;
	break;
	default:
		zend_error(E_WARNING, "Unsupported offset type");
		return NULL;
	}

	if (retval->type == PIMPLE_IS_PARAM) {
		return &retval->value;
	}

	if (zend_hash_index_exists(&pimple_obj->protected, retval->handle_num)) {
		/* Service is protected, return the value every time */
		return &retval->value;
	}

	if (zend_hash_index_exists(&pimple_obj->factories, retval->handle_num)) {
		/* Service is a factory, call it everytime and never cache its result */
		if( NULL == pimple_call_cb(object, retval, &cbrv TSRMLS_CC) ) {
			return NULL;
		}		
		ZVAL_COPY_VALUE(rv, &cbrv);
		return rv;
	}

	if (retval->initialized == 1) {
		/* Service has already been called, return its cached value */
		return &retval->value;
	}

	ZVAL_COPY_VALUE(&retval->raw, &retval->value);

	if( NULL == pimple_call_cb(object, retval, &cbrv TSRMLS_CC) ) {
		return NULL;
	}

	retval->initialized = 1;
	ZVAL_COPY_VALUE(&retval->value, &cbrv);

	return &retval->value;
}

static int pimple_zval_is_valid_callback(zval *_zval, pimple_bucket_value *_pimple_bucket_value TSRMLS_DC)
{
	if (Z_TYPE_P(_zval) != IS_OBJECT) {
		return FAILURE;
	}

	if (_pimple_bucket_value->fcc.called_scope) {
		return SUCCESS;
	}

	if (Z_OBJ_HANDLER_P(_zval, get_closure) && Z_OBJ_HANDLER_P(_zval, get_closure)(_zval, &_pimple_bucket_value->fcc.calling_scope, &_pimple_bucket_value->fcc.function_handler, &_pimple_bucket_value->fcc.object TSRMLS_CC) == SUCCESS) {
		_pimple_bucket_value->fcc.called_scope = _pimple_bucket_value->fcc.calling_scope;
		return SUCCESS;
	} else {
		return FAILURE;
	}
}

static int pimple_zval_to_pimpleval(zval *_zval, pimple_bucket_value *_pimple_bucket_value TSRMLS_DC)
{
	_pimple_bucket_value->value = *_zval;

	if (Z_TYPE_P(_zval) != IS_OBJECT) {
		return PIMPLE_IS_PARAM;
	}

	if (pimple_zval_is_valid_callback(_zval, _pimple_bucket_value TSRMLS_CC) == SUCCESS) {
		_pimple_bucket_value->type       = PIMPLE_IS_SERVICE;
		_pimple_bucket_value->handle_num = Z_OBJ_HANDLE_P(_zval);
	}

	return PIMPLE_IS_SERVICE;
}

static void pimple_bucket_dtor(zval *zv)
{
	if( Z_TYPE_P(zv) == IS_PTR ) {
		pimple_bucket_value *bucket = Z_PTR_P(zv);
		zval_ptr_dtor(&bucket->raw);
		zval_ptr_dtor(&bucket->value);
		pimple_free_bucket(bucket);
		efree(bucket);
	}
	zval_ptr_dtor(zv);
}

PHP_METHOD(Pimple, protect)
{
	zval *protected     = NULL;
	pimple_object *pobj = NULL;
	pimple_bucket_value bucket = {0};

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &protected) == FAILURE) {
		return;
	}

	if (pimple_zval_is_valid_callback(protected, &bucket TSRMLS_CC) == FAILURE) {
		pimple_free_bucket(&bucket);
		zend_throw_exception(spl_ce_InvalidArgumentException, "Callable is not a Closure or invokable object.", 0 TSRMLS_CC);
		return;
	}

	pimple_zval_to_pimpleval(protected, &bucket TSRMLS_CC);
	pobj = z_pimple_p(getThis() TSRMLS_CC);

	if (zend_hash_index_update_mem(&pobj->protected, bucket.handle_num, (void *)&bucket, sizeof(pimple_bucket_value))) {
		Z_TRY_ADDREF_P(protected);
		RETURN_ZVAL(protected, 1, 0);
	} else {
		pimple_free_bucket(&bucket);
	}
	RETURN_FALSE;
}

PHP_METHOD(Pimple, raw)
{
	zval *offset = NULL;
	pimple_object *pobj        = NULL;
	pimple_bucket_value *value = NULL;
	ulong index;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &offset) == FAILURE) {
		return;
	}

	pobj = z_pimple_p(getThis() TSRMLS_CC);

	switch (Z_TYPE_P(offset)) {
		case IS_STRING:
			value = (pimple_bucket_value *)zend_symtable_str_find_ptr(&pobj->values, Z_STRVAL_P(offset), Z_STRLEN_P(offset));
			if (!value) {
				zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "Identifier \"%s\" is not defined.", Z_STRVAL_P(offset));
				RETURN_NULL();
			}
		break;
		case IS_DOUBLE:
		case IS_TRUE:
		case IS_FALSE:
		case IS_LONG:
			if (Z_TYPE_P(offset) == IS_DOUBLE) {
				index = (ulong)Z_DVAL_P(offset);
			} else {
				index = Z_LVAL_P(offset);
			}
			value = (pimple_bucket_value *)zend_hash_index_find_ptr(&pobj->values, index);
			if (!value) {
				RETURN_NULL();
			}
		break;
		case IS_NULL:
		default:
			zend_error(E_WARNING, "Unsupported offset type");
	}

	if (!Z_ISUNDEF(value->raw)) {
		RETVAL_ZVAL(&value->raw, 1, 0);
	} else {
		RETVAL_ZVAL(&value->value, 1, 0);
	}
}

PHP_METHOD(Pimple, extend)
{
	zval *offset = NULL;
	zval *callable = NULL;
	zval pimple_closure_obj;
	pimple_bucket_value bucket = {0};
	pimple_bucket_value *value = NULL;
	pimple_object *pobj = NULL;
	pimple_closure_object *pcobj = NULL;
	ulong index;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz", &offset, &callable) == FAILURE) {
		return;
	}

	pobj = z_pimple_p(getThis() TSRMLS_CC);

	switch (Z_TYPE_P(offset)) {
		case IS_STRING:
			value = (pimple_bucket_value *)zend_symtable_str_find_ptr(&pobj->values, Z_STRVAL_P(offset), Z_STRLEN_P(offset));
			if (!value) {
				zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "Identifier \"%s\" is not defined.", Z_STRVAL_P(offset));
				RETURN_NULL();
			}
			if (value->type != PIMPLE_IS_SERVICE) {
				zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "Identifier \"%s\" does not contain an object definition.", Z_STRVAL_P(offset));
				RETURN_NULL();
			}
		break;
		case IS_DOUBLE:
		case IS_TRUE:
		case IS_FALSE:
		case IS_LONG:
			if (Z_TYPE_P(offset) == IS_DOUBLE) {
				index = (ulong)Z_DVAL_P(offset);
			} else {
				index = Z_LVAL_P(offset);
			}
			value = (pimple_bucket_value *) zend_hash_index_find_ptr(&pobj->values, index);
			if (!value) {
				zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "Identifier \"%ld\" is not defined.", index);
				RETURN_NULL();
			}
			if (value->type != PIMPLE_IS_SERVICE) {
				zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "Identifier \"%ld\" does not contain an object definition.", index);
				RETURN_NULL();
			}
		break;
		case IS_NULL:
		default:
			zend_error(E_WARNING, "Unsupported offset type");
	}

	if (pimple_zval_is_valid_callback(callable, &bucket TSRMLS_CC) == FAILURE) {
		pimple_free_bucket(&bucket);
		zend_throw_exception(spl_ce_InvalidArgumentException, "Extension service definition is not a Closure or invokable object.", 0 TSRMLS_CC);
		RETURN_NULL();
	}
	pimple_free_bucket(&bucket);

	object_init_ex(&pimple_closure_obj, pimple_closure_ce);

	pcobj = z_pimple_closure_p(&pimple_closure_obj TSRMLS_CC);
	pcobj->callable = *callable;
	pcobj->factory  = value->value;
	Z_TRY_ADDREF_P(callable);
	Z_TRY_ADDREF_P(&value->value);

	if (zend_hash_index_exists(&pobj->factories, value->handle_num)) {
		pimple_zval_to_pimpleval(&pimple_closure_obj, &bucket TSRMLS_CC);
		zend_hash_index_del(&pobj->factories, value->handle_num);
		zend_hash_index_update_mem(&pobj->factories, bucket.handle_num, (void *)&bucket, sizeof(pimple_bucket_value));
		Z_TRY_ADDREF_P(&pimple_closure_obj);
	}

	zval tmp;
	ZVAL_PTR(&tmp, &pimple_closure_obj);
	pimple_object_write_dimension(getThis(), offset, &tmp TSRMLS_CC);

	RETVAL_ZVAL(&pimple_closure_obj, 1, 1);
}

PHP_METHOD(Pimple, keys)
{
	HashPosition pos;
	pimple_object *pobj = NULL;
	zval *value        = NULL;
	zval endval;
	zend_string *str_index = NULL;
	int str_len;
	ulong num_index;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	pobj = z_pimple_p(getThis() TSRMLS_CC);
	array_init_size(return_value, zend_hash_num_elements(&pobj->values));

	ZEND_HASH_FOREACH_KEY_VAL(&pobj->values, num_index, str_index, value) {
		if( str_index ) {
			ZVAL_STR(&endval, str_index);
		} else {
			ZVAL_LONG(&endval, num_index);
		}
		zend_hash_next_index_insert(Z_ARRVAL_P(return_value), &endval);
	} ZEND_HASH_FOREACH_END();
}

PHP_METHOD(Pimple, factory)
{
	zval *factory       = NULL;
	pimple_object *pobj = NULL;
	pimple_bucket_value bucket = {0};

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &factory) == FAILURE) {
		return;
	}

	if (pimple_zval_is_valid_callback(factory, &bucket TSRMLS_CC) == FAILURE) {
		pimple_free_bucket(&bucket);
		zend_throw_exception(spl_ce_InvalidArgumentException, "Service definition is not a Closure or invokable object.", 0 TSRMLS_CC);
		return;
	}

	pimple_zval_to_pimpleval(factory, &bucket TSRMLS_CC);
	pobj = z_pimple_p(getThis() TSRMLS_CC);

	if (zend_hash_index_update_mem(&pobj->factories, bucket.handle_num, (void *)&bucket, sizeof(pimple_bucket_value))) {
		Z_TRY_ADDREF_P(factory);
		RETURN_ZVAL(factory, 1, 0);
	} else {
		pimple_free_bucket(&bucket);
	}

	RETURN_FALSE;
}

PHP_METHOD(Pimple, offsetSet)
{
	zval *offset = NULL;
	zval *value = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz", &offset, &value) == FAILURE) {
		return;
	}

	pimple_object_write_dimension(getThis(), offset, value TSRMLS_CC);
}

PHP_METHOD(Pimple, offsetGet)
{
	zval *offset = NULL;
	zval *value = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &offset) == FAILURE) {
		return;
	}

	value = pimple_object_read_dimension(getThis(), offset, 0, return_value TSRMLS_CC);
	if (value != return_value) {
		ZVAL_DEREF(value);
		ZVAL_COPY(return_value, value);
	}
}

PHP_METHOD(Pimple, offsetUnset)
{
	zval *offset = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &offset) == FAILURE) {
		return;
	}

	pimple_object_unset_dimension(getThis(), offset TSRMLS_CC);
}

PHP_METHOD(Pimple, offsetExists)
{
	zval *offset = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &offset) == FAILURE) {
		return;
	}

	RETVAL_BOOL(pimple_object_has_dimension(getThis(), offset, 1 TSRMLS_CC));
}

PHP_METHOD(Pimple, register)
{
	zval *provider;
	zval retval;

	HashTable *array = NULL;
	ulong num_index;
	zend_string *str_index;
	zval *data;
	zval offset;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O|h", &provider, pimple_serviceprovider_ce, &array) == FAILURE) {
		return;
	}

	RETVAL_ZVAL(getThis(), 1, 0);

	zend_call_method_with_1_params(provider, Z_OBJCE_P(provider), NULL, "register", &retval, getThis());

	/*if (retval) {
		zval_ptr_dtor(&retval);
	}*/

	if (!array) {
		return;
	}

	ZEND_HASH_FOREACH_KEY_VAL(array, num_index, str_index, data) {
		if( str_index ) {
			ZVAL_STR(&offset, str_index);
		} else {
			ZVAL_LONG(&offset, num_index);
		}
		pimple_object_write_dimension(getThis(), &offset, data);
	} ZEND_HASH_FOREACH_END();
}

PHP_METHOD(Pimple, __construct)
{
	zval *values = NULL;
	zval *data = NULL;
	zval offset;
	zend_string *str_index;
	ulong num_index;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|a!", &values) == FAILURE || !values) {
		return;
	}

	ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(values), num_index, str_index, data) {
		if( str_index ) {
			ZVAL_STR(&offset, str_index);
		} else {
			ZVAL_LONG(&offset, num_index);
		}
		pimple_object_write_dimension(getThis(), &offset, data);
	} ZEND_HASH_FOREACH_END();
}

/*
 * This is PHP code snippet handling extend()s calls :

  $extended = function ($c) use ($callable, $factory) {
      return $callable($factory($c), $c);
  };

 */
PHP_METHOD(PimpleClosure, invoker)
{
	pimple_closure_object *pcobj = NULL;
	zval arg = EG(uninitialized_zval);
	zval retval = EG(uninitialized_zval);
	zval newretval = EG(uninitialized_zval);
	zend_fcall_info fci = {0};
	zval args[2];

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &arg) == FAILURE) {
		return;
	}

	pcobj = z_pimple_closure_p(getThis() TSRMLS_CC);

	fci.function_name = pcobj->factory;
	args[0] = arg;
	zend_fcall_info_argp(&fci TSRMLS_CC, 1, args);
	fci.retval = &retval;
	fci.size = sizeof(fci);

	if (zend_call_function(&fci, NULL TSRMLS_CC) == FAILURE || EG(exception)) {
		efree(fci.params);
		return; /* Should here return default zval */
	}

	efree(fci.params);
	memset(&fci, 0, sizeof(fci));
	fci.size = sizeof(fci);

	fci.function_name = pcobj->callable;
	args[0] = retval;
	args[1] = arg;
	zend_fcall_info_argp(&fci TSRMLS_CC, 2, args);
	fci.retval = &newretval;

	if (zend_call_function(&fci, NULL TSRMLS_CC) == FAILURE || EG(exception)) {
		efree(fci.params);
		zval_ptr_dtor(&retval);
		return;
	}

	efree(fci.params);
	zval_ptr_dtor(&retval);

	RETVAL_ZVAL(&newretval, 1, 1);
}

PHP_MINIT_FUNCTION(pimple)
{
	zend_class_entry tmp_pimple_ce, tmp_pimple_closure_ce, tmp_pimple_serviceprovider_iface_ce;
	INIT_NS_CLASS_ENTRY(tmp_pimple_ce, PIMPLE_NS, "Container", pimple_ce_functions);
	INIT_NS_CLASS_ENTRY(tmp_pimple_closure_ce, PIMPLE_NS, "ContainerClosure", NULL);
	INIT_NS_CLASS_ENTRY(tmp_pimple_serviceprovider_iface_ce, PIMPLE_NS, "ServiceProviderInterface", pimple_serviceprovider_iface_ce_functions);

	tmp_pimple_ce.create_object         = pimple_object_create;
	tmp_pimple_closure_ce.create_object = pimple_closure_object_create;

	pimple_ce = zend_register_internal_class(&tmp_pimple_ce TSRMLS_CC);
	zend_class_implements(pimple_ce TSRMLS_CC, 1, zend_ce_arrayaccess);

	pimple_closure_ce = zend_register_internal_class(&tmp_pimple_closure_ce TSRMLS_CC);
	pimple_closure_ce->ce_flags |= ZEND_ACC_FINAL;

	pimple_serviceprovider_ce = zend_register_internal_interface(&tmp_pimple_serviceprovider_iface_ce TSRMLS_CC);

	memcpy(&pimple_closure_object_handlers, zend_get_std_object_handlers(), sizeof(*zend_get_std_object_handlers()));
	pimple_object_handlers                     = std_object_handlers;
	pimple_object_handlers.offset = XtOffsetOf(pimple_object, zobj);
	pimple_object_handlers.free_obj = pimple_free_object_storage;

	pimple_closure_object_handlers.get_closure = pimple_closure_get_closure;
	pimple_closure_object_handlers.get_constructor = pimple_closure_get_constructor;
	pimple_closure_object_handlers.offset = XtOffsetOf(pimple_closure_object, zobj);
	pimple_closure_object_handlers.free_obj = pimple_closure_free_object_storage;

	pimple_closure_invoker_function.function_name     = zend_string_init(ZEND_STRL("Pimple closure internal invoker"), 0);
	pimple_closure_invoker_function.fn_flags         |= ZEND_ACC_CLOSURE;
	pimple_closure_invoker_function.handler           = ZEND_MN(PimpleClosure_invoker);
	pimple_closure_invoker_function.num_args          = 1;
	pimple_closure_invoker_function.required_num_args = 1;
	pimple_closure_invoker_function.scope             = pimple_closure_ce;
	pimple_closure_invoker_function.type              = ZEND_INTERNAL_FUNCTION;
	pimple_closure_invoker_function.module            = &pimple_module_entry;

	return SUCCESS;
}

PHP_MINFO_FUNCTION(pimple)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "SensioLabs Pimple C support", "enabled");
	php_info_print_table_row(2, "Pimple supported version", PIMPLE_VERSION);
	php_info_print_table_end();

	php_info_print_box_start(0);
	php_write((void *)ZEND_STRL("SensioLabs Pimple C support developed by Julien Pauli") TSRMLS_CC);
	if (!sapi_module.phpinfo_as_text) {
		php_write((void *)ZEND_STRL(sensiolabs_logo) TSRMLS_CC);
	}
	php_info_print_box_end();
}

zend_module_entry pimple_module_entry = {
	STANDARD_MODULE_HEADER,
	"pimple",
	NULL,
	PHP_MINIT(pimple),
	NULL,
	NULL,
	NULL,
	PHP_MINFO(pimple),
	PIMPLE_VERSION,
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_PIMPLE
ZEND_GET_MODULE(pimple)
#endif

