/** acl */

var util = require('util');
var is = require('nor-is');
var debug = require('nor-debug');
var Q = require('q');
var acl = module.exports = {};

var nor_express = require('nor-express');
var HTTPError = nor_express.HTTPError;
var assert_route = nor_express.assert;

function is_true(x) {
	return (x === true) ? true : false;
}

function is_false(x) {
	return (x === false) ? true : false;
}

/** Handle request access control by access control list */
acl.request = function(opts) {
	opts = opts || {};
	var routes_file = opts.routes;
	debug.assert(routes_file).is('string');
	var routes_json = require('nor-routes-json').load(routes_file);

	return function(req, res) {
		return Q.fcall(function() {

			debug.assert(req).is('object');
			debug.assert(res).is('object');

			//debug.log('req.route = ', req.route);
			//debug.log('req.flags = ', req.flags);

			debug.assert(req.route).is('object');
			debug.assert(req.flags).is('object');

			assert_route.handlers(req, res);

			// Current access flags
			var flags = req.flags;

			// Current request information
			var route = req.route || {};
			var path = route.path;
			var method = (''+(route.method || 'get')).toLowerCase();
			//debug.log('path = ', path);
			//debug.log('method = ', method);

			debug.assert(path).is('string');
			debug.assert(method).is('string');

			var routes = routes_json.find({path:path, method:method});
			//debug.log('routes = ', routes);
			//debug.assert(routes).is('array').length(1);
			if(routes.length >= 2) {
				debug.warn('More than two routes detected, we will use only first!');
				// FIXME: should we merge more than one item?	
			}	
			routes = routes.shift();

			if(!is.obj(routes)) {
				debug.warn('No config found for route ' + method + ' ' + path + ', using default which accepts all traffic.');
				routes = {
					'flags': {
						'public': true
					}
				};
			}
		
			// Check information

			//debug.log('flags = ', flags);
			debug.assert(flags).is('object');

			var accepts;

			var flag_keys = Object.keys(routes.flags);
			if(flag_keys.length >= 1) {
				accepts = flag_keys.map(function(flag) {
					if( is_true(routes.flags[flag]) && is_true(flags[flag]) ) {
						return true;
					}
					if( is_false(routes.flags[flag]) && (!is_true(flags[flag])) ) {
						return true;
					}
				}).every(is_true);
			}

			if(!is_true(accepts)) {
				debug.warn('Access denied to ' + method + ' ' + path);
				throw new HTTPError(404);
			}
		});
	};
};

/** Express plugin */
acl.plugin = function(opts) {
	//debug.log('here');
	var check = acl.request(opts);
	debug.assert(check).is('function');
	return function(req, res, next) {
		//debug.log('here');
		debug.assert(req).is('object');
		debug.assert(req.route).is('object');
		debug.assert(res).is('object');
		debug.assert(next).is('function');
		check(req, res).then(function() {
			//debug.log('here');
			next();
		}).fail(function(err) {
			debug.error(err);
			next(err);
		}).done();
	};
};

/* EOF */
