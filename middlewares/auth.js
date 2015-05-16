
var mongoose = require('mongoose');
var UserModel = mongoose.model('User');
var Message = require('../proxy').Message;
var config = require('../config');
var eventproxy = require('eventproxy');
var UserProxy = require('../proxy').User;
var superagent = require('superagent');

/**
 * 需要管理员权限
 */
exports.adminRequired = function (req, res, next) {
  if (!req.session.user) {
    return res.render('notify/notify', {error: '你还没有登录。'});
  }
  if (!req.session.user.is_admin) {
    return res.render('notify/notify', {error: '需要管理员权限。'});
  }
  next();
};

/**
 * 需要登录
 */
exports.userRequired = function (req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(403).send('forbidden!');
  }
  next();
};

exports.blockUser = function () {
  return function (req, res, next) {
    if (req.path === '/signout') {
      return next();
    }
    if (req.session.user && req.session.user.is_block && req.method !== 'GET') {
      return res.status(403).send('您已被管理员屏蔽了。有疑问请联系 @alsotang。');
    }
    next();
  };
};


function gen_session(user, res) {
  var auth_token = user._id + '$$$$'; // 以后可能会存储更多信息，用 $$$$ 来分隔
  res.cookie(config.auth_cookie_name, auth_token,
    {path: '/', maxAge: 1000 * 60 * 60 * 24 * 30, signed: true, httpOnly: true}); //cookie 有效期30天
}

function gen_weixin_session (weixin, res) {
  var auth_token = 'openid=' + weixin.openid + '$$$$' + 'is_weixin_auth=' + weixin.is_weixin_auth; // 以后可能会存储更多信息，用 $$$$ 来分隔
  res.cookie(config.auth_weixin_cookie_name, auth_token,
    {path: '/', signed: true, maxAge: 1000 * 60, httpOnly: true});
}

exports.gen_session = gen_session;
exports.gen_weixin_session = gen_weixin_session;

function _gen_weixin_session (res) {
  weixin = {};
  weixin.openid = 'default';
  weixin.is_weixin_auth = '0';
  gen_weixin_session(weixin, res);
}

// 微信auth
exports.authWeixin = function (req, res, next) {
  var ep = new eventproxy();
  ep.fail(next);
  // if (config.debug && req.cookies['mock_user']) {
  //   var mockUser = JSON.parse(req.cookies['mock_user']);
  //   req.session.user = new UserModel(mockUser);
  //   if (mockUser.is_admin) {
  //     req.session.user.is_admin = true;
  //   }
  //   return next();
  // }
  var authorizeUrl = config.weixin.authorizeUrl;
  var appid = config.weixin.appid;
  var secret = config.weixin.secret;
  var redirectUri = config.weixin.redirectUri;
  var scope = 'snsapi_base';
  var redirectBaseUrl = authorizeUrl + '?appid=' + appid + '&redirect_uri=' + encodeURIComponent(redirectUri) + '&response_type=code&scope=' + scope + '&state=STATE#wechat_redirect';
  var redirectInfoUrl = authorizeUrl + '?appid=' + appid + '&redirect_uri=' + encodeURIComponent(redirectUri) + '&response_type=code&scope=snsapi_userinfo&state=STATE#wechat_redirect';
  
  ep.all('get_weixin', function (user) {
    if (!user) {
      var weixin = {};
      weixin.openid = 'default';
      weixin.is_weixin_auth = '1';
      gen_weixin_session(weixin, res);
      res.redirect(redirectInfoUrl);
      return;
    }
    next();
  });

  if (req.session.weixin) {
    ep.emit('get_weixin', req.session.weixin);
  } else {
    var auth_token = req.signedCookies[config.auth_weixin_cookie_name];
    if (!auth_token) {
      _gen_weixin_session(res);
      res.redirect(redirectBaseUrl);
      return;
    } else {
      var auth = auth_token.split('$$$$');
      var openid = auth[0].split('=')[1];
      var is_weixin_auth = auth[1].split('=')[1];
      if (is_weixin_auth === '0') {
        var code = req.query.code;
        if (code) {
          var auth_url = 'https://api.weixin.qq.com/sns/oauth2/access_token?appid=' + appid + '&secret=' + secret + '&code=' + code + '&grant_type=authorization_code';
          superagent
          .get(auth_url)
          .end(function(authres){
            console.log(authres);
            // var User = UserProxy.getUserByWeixinOpenId(res.body.openid, ep.done('get_weixin'));
          });
        }
      } else if (is_weixin_auth === '1') {
        var code = req.query.code;
        if (code) {
          console.log(code);
          superagent
          .get('https://api.weixin.qq.com/sns/oauth2/access_token')
          .query({appid: appid, secret: secret, code: code, grant_type: 'authorization_code'})
          .end(function(res){
              superagent
              .get('https://api.weixin.qq.com/sns/userinfo?access_token=ACCESS_TOKEN&openid=OPENID&lang=zh_CN')
              .query({access_token: res.body.access_token, openid: res.body.openid, lang: 'zh_CN'})
              .end(function(res){
                console.log(res);
                // var User = UserProxy.getUserByWeixinOpenId(openid, ep.done('get_weixin'));
              });
          });
        }
      } else {
        _gen_weixin_session(res);
        res.redirect(redirectBaseUrl);
        return;
      }
      return next();
    }
  }
};


// 验证用户是否登录
exports.authUser = function (req, res, next) {
  var ep = new eventproxy();
  ep.fail(next);

  if (config.debug && req.cookies['mock_user']) {
    var mockUser = JSON.parse(req.cookies['mock_user']);
    req.session.user = new UserModel(mockUser);
    if (mockUser.is_admin) {
      req.session.user.is_admin = true;
    }
    return next();
  }

  ep.all('get_user', function (user) {
    if (!user) {
      return next();
    }
    user = res.locals.current_user = req.session.user = new UserModel(user);

    if (config.admins.hasOwnProperty(user.loginname)) {
      user.is_admin = true;
    }
    Message.getMessagesCount(user._id, ep.done(function (count) {
      user.messages_count = count;
      next();
    }));

  });

  if (req.session.user) {
    ep.emit('get_user', req.session.user);
  } else {
    var auth_token = req.signedCookies[config.auth_cookie_name];
    if (!auth_token) {
      return next();
    }

    var auth = auth_token.split('$$$$');
    var user_id = auth[0];
    UserProxy.getUserById(user_id, ep.done('get_user'));
  }
};
