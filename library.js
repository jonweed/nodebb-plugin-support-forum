"use strict";

var winston = module.parent.require('winston'),
	User = module.parent.require('./user'),
	Posts = module.parent.require('./posts'),
	Topics = module.parent.require('./topics'),
	Categories = module.parent.require('./categories'),
	Meta = module.parent.require('./meta'),
	db = module.parent.require('./database'),
	async = module.parent.require('async'),

	plugin = {};

plugin.init = function(params, callback) {
	var app = params.router,
		middleware = params.middleware,
		controllers = params.controllers;

	app.get('/admin/plugins/support-forum', middleware.admin.buildHeader, renderAdmin);
	app.get('/api/admin/plugins/support-forum', renderAdmin);

	// Retrieve configs
	Meta.settings.get('support-forum', function(err, config) {
		plugin.config = config;
	});

	callback();
};

/* Meat */

plugin.isAllowed = function(uid,cid, callback) {
	async.parallel({
		isModerator: async.apply(User.isModerator, uid, cid),
		isAdminOrGlobalMod: async.apply(User.isAdminOrGlobalMod, uid)
	}, function(err, priv) {
		priv.isAllowed = (!priv.isAdminOrGlobalMod && !priv.isModerator)
		? false
		: true; 

		return (callback) ? callback(null, priv) : priv;
	});
};

plugin.supportify = function(data, callback) {	// There are only two hard things in Computer Science: cache invalidation and naming things. -- Phil Karlton
	plugin.isAllowed(data.uid, parseInt(plugin.config.cid, 10), function(err, priv) {
		if ((!priv.isAllowed) && parseInt(data.cid, 10) === parseInt(plugin.config.cid, 10)) {
			winston.verbose('[plugins/support-forum] Support forum accessed by uid ' + data.uid);
			data.targetUid = data.uid;
			callback(null, data);
		} else {
			callback(null, data);
		}
	});
};

plugin.restrict = {};

plugin.restrict.topic = function(privileges, callback) {
	async.parallel({
		topicObj: async.apply(Topics.getTopicFields, privileges.tid, ['cid', 'uid']),
		priv: async.apply(plugin.isAllowed, privileges.uid, parseInt(plugin.config.cid, 10))
	}, function(err, data) {
		if (parseInt(data.topicObj.cid, 10) === parseInt(plugin.config.cid, 10) && parseInt(data.topicObj.uid, 10) !== parseInt(privileges.uid, 10) && !data.priv.isAllowed) {
			winston.verbose('[plugins/support-forum] tid ' + privileges.tid + ' (author uid: ' + data.topicObj.uid + ') access attempt by uid ' + privileges.uid + ' blocked.');
			privileges.read = false;
			privileges['topics:read'] = false;
		}
		callback(null, privileges);
	});
};

plugin.restrict.category = function(privileges, callback) {
	if (parseInt(privileges.cid, 10) === parseInt(plugin.config.cid, 10)) {
		// Override existing privileges so that regular users can enter and create topics
		var allowed = parseInt(privileges.uid, 10) > 0
		privileges.read = allowed;
		privileges['topics:create'] = allowed;

		if (!allowed) {
			winston.verbose('[plugins/support-forum] Access to cid ' + privileges.cid + ' by guest blocked.');
		}

		callback(null, privileges);
	} else {
		callback(null, privileges);
	}
};

plugin.filterPids = function(data, callback) {
	plugin.isAllowed(data.uid, parseInt(plugin.config.cid, 10), function(err, privileges) {
		if (!privileges.isAllowed) {
			async.waterfall([
				async.apply(Posts.getCidsByPids, data.pids),
				function(cids, next) {
					Posts.getPostsFields(data.pids, ['uid'], function(err, fields) {
						data.pids = fields.reduce(function(prev, cur, idx) {
							if (parseInt(cids[idx], 10) !== parseInt(plugin.config.cid, 10) || parseInt(cur.uid, 10) === parseInt(data.uid, 10)) {
								prev.push(data.pids[idx]);
							}
							return prev;
						}, []);

						callback(null, data);
					});
				}
			]);
		} else {
			callback(null, data);
		}
	});
};

plugin.filterTids = function(data, callback) {
	plugin.isAllowed(data.uid, parseInt(plugin.config.cid, 10), function(err, privileges) {
		if (!privileges.isAllowed) {
			Topics.getTopicsFields(data.tids, ['cid', 'uid'], function(err, fields) {
				data.tids = fields.reduce(function(prev, cur, idx) {
					if (parseInt(cur.cid, 10) !== parseInt(plugin.config.cid, 10) || parseInt(cur.uid, 10) === parseInt(data.uid, 10)) {
						prev.push(data.tids[idx]);
					}
					return prev;
				}, []);

				callback(null, data);
			});
		} else {
			callback(null, data);
		}
	});
};

plugin.filterCategory = function(data, callback) {
	if (plugin.config.ownOnly=='on') {
		plugin.isAllowed(data.uid, parseInt(plugin.config.cid, 10), function(err, privileges) {
			if (!privileges.isAllowed) {
				var filtered = [];
				if (data.topics && data.topics.length) {
					data.topics.forEach( function(topic) {
						if (parseInt(topic.cid, 10) !== parseInt(plugin.config.cid, 10) || parseInt(topic.uid, 10) === parseInt(data.uid)) {
							filtered.push(topic);
						}
					});
				}
				callback(null, {topics:filtered,uid:data.uid});
			} else {
				callback(null, data);
			}
		});
	} else {
		callback(null, data);
	}
};

plugin.templateData = function(data, callback) {
	if (data.templateData.template.categories) {
		for (var i=0,ii=data.templateData.categories.length; i < ii; i++) {
			if (parseInt(data.templateData.categories[i].cid,10) == parseInt(plugin.config.cid, 10)) {
				data.templateData.categories[i].supportForum = true;
			}
		}
	}

	else if (data.templateData.template.category) {
		if (parseInt(data.templateData.cid,10) == parseInt(plugin.config.cid, 10)) {
			data.templateData.supportForum = true;
		}
	}

	else if (data.templateData.template.topic) {
		if (parseInt(data.templateData.category.cid,10) == parseInt(plugin.config.cid, 10)) {
			data.templateData.supportForum = true;
		}
	}

	callback(null, data);
};


/* Admin stuff */

plugin.addAdminNavigation = function(header, callback) {
	header.plugins.push({
		route: '/plugins/support-forum',
		icon: 'fa-question',
		name: 'Support Forum'
	});

	callback(null, header);
};

function renderAdmin(req, res, next) {
	Categories.getAllCategories(req.user.uid, function(err, categories) {
		res.render('admin/plugins/support-forum', {
			categories: categories.map(function(category) {
				return {
					cid: category.cid,
					name: category.name
				}
			})
		});
	});
}

module.exports = plugin;
