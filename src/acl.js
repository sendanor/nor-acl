/** Express Access Control List Module */

var util = require('util');
var is = require('nor-is');
var debug = require('nor-debug');
var Q = require('q');
var acl = module.exports = {};

var nor_express = require('nor-express');
var HTTPError = nor_express.HTTPError;
var assert_route = nor_express.assert;

/** Copy an object */
function copy(x) {
	return JSON.parse(JSON.stringify(x));
}

/** Returns `true` if `x` is `true`, otherwise `false`. */
function is_true(x) {
	return !!(x === true);
}

/** Returns `true` if `x` is `false`, otherwise `false`. */
function is_false(x) {
	return !!(x === false);
}

/** */
function check_flags(routes, user_flags) {

	/** Returns `true` if `user_flags` has flag `f` and it is `true`. Otherwise returns `false`. */
	function user_has_flag(f) {
		return is_true(user_flags[f]);
	}

	var route_flags = Object.keys(routes.flags);

	// If the route has no flags set, we cannot accept anything.
	if(route_flags.length <= 0) {
		return false;
	}

	// Get list of flags to accept
	var accept_flags = route_flags.filter(function(flag) {
		return is_true(routes.flags[flag]);
	});

	// Get list of flags to reject
	var reject_flags = route_flags.filter(function(flag) {
		return is_false(routes.flags[flag]);
	});

	// Reject if user has a flag in the reject flag list
	if( (reject_flags.length !== 0) && reject_flags.some(user_has_flag) ) {
		return false;
	}

	// Accept if user has a flag in the accept flag list
	return !!( (accept_flags.length !== 0) && accept_flags.some(user_has_flag) );

	/*
	return route_flags.map(function(flag) {
		if( is_true(routes.flags[flag]) && is_true(user_flags[flag]) ) {
			return true;
		}
		if( is_false(routes.flags[flag]) && (!is_true(user_flags[flag])) ) {
			return true;
		}
	}).every(is_true);
	*/
}

/** Handle request access control by access control list */
acl.request = function acl_request(opts) {


	opts = opts || {};
	debug.assert(opts).is('object');

	var routes_file = opts.routes;
	debug.assert(routes_file).is('string');

	var routes_json = require('nor-routes-json').load(routes_file);

	if(opts.defaultACL === undefined) {
		opts.defaultACL = {
			'flags': {
				'admin': true
			}
		};
	}

	debug.assert(opts.defaultACL).is('object');

	function noop_keys() {
		return true;
	}

	opts.keys = opts.keys || noop_keys;

	debug.assert(opts.keys).is('function');

	return function acl_request_handler(req, res) {
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
			debug.assert(flags).is('object');
			//debug.log('flags = ', flags);

			// Current request information
			var route = req.route || {};
			var path = route.path;
			var method = (''+(route.method || 'get')).toLowerCase();
			//debug.log('path = ', path);
			//debug.log('method = ', method);

			debug.assert(path).is('string');
			debug.assert(method).is('string');

			var routes = routes_json.findTarget(path, method);

			//debug.log('routes = ', routes);
			//debug.assert(routes).is('array').length(1);
			if(routes.length >= 2) {
				debug.warn('[', method.toUpperCase(), ' ', path, '] More than two routes detected, we will use only first!');
				// FIXME: should we merge more than one item?
			}
			routes = routes.shift();

			if(!is.obj(routes)) {
				debug.warn('[', method.toUpperCase(), ' ', path, '] No config found for route, using the default: ', opts.defaultACL);
				routes = copy(opts.defaultACL);
			}

			/* Check information */
			//debug.log("routes = ", routes);

			var checks = [];

			/* Check flags */
			checks.push(Q.fcall(check_flags.bind(undefined, routes, flags)));

			/* Check keys */
			if(is.array(routes.keys) && routes.keys.length > 0) {
				//var params = req.params || {};
				//debug.assert(params).is('object');

				routes.keys.forEach(function(key) {
					//debug.log('key = ', key);
					//return Q( opts.keys(key, req, res) );
					checks.push( opts.keys(key, req, res) );
				});
			}

			return Q.allSettled(checks).then(function(results) {
				debug.assert(results).is('array');

				//debug.log('results =', results);

				var accepts = results.map(function(result) { if(result.state === 'fulfilled') { return result.value; } }).every(is_true);
				debug.assert(accepts).is('boolean');

				/* Check accepts */
				//debug.log("accepts = ", accepts);

				if(! is_true(accepts) ) {
					debug.warn('Access denied to ' + method + ' ' + path);
					throw new HTTPError(404);
				}
			});
		});
	};
};

/** Express plugin */
acl.plugin = function acl_plugin(opts) {
	//debug.log('here');
	var check = acl.request(opts);
	debug.assert(check).is('function');
	return function acl_plugin_handler(req, res, next) {
		//debug.log('here');
		debug.assert(req).is('object');
		debug.assert(req.route).is('object');
		debug.assert(res).is('object');
		debug.assert(next).is('function');
		check(req, res).then(function() {
			//debug.log('here');
			next();
		}).fail(function(err) {
			//debug.error('Passing on error: ' + err);
			next(err);
		}).done();
	};
};

/* EOF */
