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
		isAdministrator: async.apply(User.isAdministrator, uid)
	}, function(err, priv) {
		priv.isAllowed = (!priv.isAdministrator) ? false : true;
		if ((plugin.config.allowMods=='on') && !priv.isAllowed && priv.isModerator) {
			priv.isAllowed = true;
		}

		return (callback) ? callback(null, priv) : priv;
	});
};

plugin.supportify = function(data, callback) {
	plugin.isAllowed(data.uid, parseInt(plugin.config.cid, 10), function(err, priv) {
		if ((!priv.isAllowed) && parseInt(data.cid, 10) === parseInt(plugin.config.cid, 10)) {
			winston.verbose('[plugins/support-forum] Support forum accessed by uid ' + data.uid);
			data.targetUid = data.uid;
		}
		callback(null, data);
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

						next(null, data);
					});
				}
			], callback);
		} else {
			callback(null, data);
		}
	});
};

plugin.filterTids = function(data, callback) {
	plugin.isAllowed(data.uid, parseInt(plugin.config.cid, 10), function(err, privileges) {
		if (!privileges.isAllowed) {

			async.waterfall([
				async.apply(Topics.getTopicsFields, data.tids, ['cid', 'uid']),
				function(fields, next) {
					data.tids = fields.reduce(function(prev, cur, idx) {
						if (parseInt(cur.cid, 10) !== parseInt(plugin.config.cid, 10) || parseInt(cur.uid, 10) === parseInt(data.uid, 10)) {
							prev.push(data.tids[idx]);
						}
						return prev;
					}, []);
					next(null,data);
				},
			], callback);
		} else {
			callback(null, data);
		}
	});
};

plugin.filterCategory = function(data, callback) {
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
};

plugin.filterNewPost = function(data, callback) {
	if (parseInt(data.post.cid,10) === parseInt(plugin.config.cid, 10)) {
		async.filter(data.uidsTo, function(uid, callback) {
			plugin.isAllowed(uid, parseInt(plugin.config.cid, 10), function(err, privileges) {
				if (privileges.isAllowed) {
					callback(null, true);
				}
				else {
					Topics.getTopicField(data.post.topic.tid, 'uid', function(err, tuid) {
						callback(null, parseInt(uid, 10) == parseInt(tuid, 10));
					});
				}
			});
		}, function(err, results) {
			data.uidsTo=results;
			callback(null, data);
		});
	}
	else {
		callback(null, data);
	}
};


plugin.recentReplies = function(data, callback) {
	async.parallel({
		topics: async.apply(Topics.getTopicsFields, data.tids, ['uid','tid','cid']),
		privs: async.apply(plugin.isAllowed, data.uid, parseInt(plugin.config.cid, 10)),
		latestPost: async.apply(plugin.getLatestPost, data)
	}, function(err, results) {
		var filtered = [];
		results.topics.forEach( function(topic) {
			if (parseInt(topic.cid, 10) == parseInt(plugin.config.cid, 10)) {
				if (parseInt(topic.uid, 10) === parseInt(data.uid) || results.privs.isAllowed) {
					filtered.push(topic.tid);
				}
				else if (results.latestPost) { filtered.push(results.latestPost); }
			}
			else {
				filtered.push(topic.tid);
			}
		});
		callback(null, filtered);
	});
};

plugin.getTopicCount = function(data, callback) {
	async.waterfall([
		async.apply(db.getSortedSetRevRange, 'cid:'+parseInt(plugin.config.cid, 10)+':uid:'+parseInt(data.uid, 10)+':tids', 0, -1),
		function(tids, next) {
			var stats={topicCount: tids.length, postCount: 0};
			async.each(tids, function(tid, _next) {
				Topics.getPids(tid, function(err,pids) {
					stats.postCount += pids.length;
					_next();
				});
			}, function(err){
				next(null, stats);
			});
		}
	], callback);
};


plugin.getLatestPost = function(data, callback) {
	async.waterfall([
		async.apply(db.getSortedSetRevRange, 'cid:'+parseInt(plugin.config.cid, 10)+':uid:'+parseInt(data.uid, 10)+':tids', 0, 0),
		function (tids, next) {
			Topics.getPids(tids[0], next);
		},
		function (pids, next) {
			if (pids.length) {
				Posts.getPostData(pids[0], function(err, post) {
					next(null, post.tid);
				});
			}
			else {
				next(null, false);
			}
		}
	], callback);
};

plugin.categoriesData = function(data, callback) {
	plugin.isAllowed(data.req.uid, parseInt(plugin.config.cid, 10), function(err, privileges) {
		async.map(data.templateData.categories, function(category, next){
			if (parseInt(category.cid,10) == parseInt(plugin.config.cid, 10)) {
				category.supportForum = true;
				if (privileges.isAllowed) {
					category['supportForum:mod'] = true;
					category['supportForum:stats'] = {topicCount: category.totalTopicCount, postCount: category.totalPostCount};
					next(null, category);
				}
				else {
					category['reputation:disabled']=!privileges.isAllowed;
					plugin.getTopicCount({uid:data.req.uid}, function(err, stats) {
						category['supportForum:stats'] = stats;
						next(null, category);
					})
				}
			}
			else {
				next(null, category);
			}
		}, function(err, results) {
			callback(null, data);
		});
	});
};

plugin.categoryData = function(data, callback) {
	if (parseInt(data.templateData.cid,10) == parseInt(plugin.config.cid, 10)) {
		data.templateData.supportForum = true;
		plugin.isAllowed(data.req.uid, parseInt(plugin.config.cid, 10), function(err, privileges) {
			data.templateData['reputation:disabled']=!privileges.isAllowed;
		});
	}

	callback(null, data);
};

plugin.topicData = function(data, callback) {
	if (parseInt(data.templateData.category.cid,10) == parseInt(plugin.config.cid, 10)) {
		data.templateData.supportForum = true;
		plugin.isAllowed(data.req.uid, parseInt(plugin.config.cid, 10), function(err, privileges) {
			data.templateData['reputation:disabled']=!privileges.isAllowed;
		});
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
