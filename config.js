/**
 * config
 */

var path = require('path');

var config = {
  // debug 为 true 时，用于本地调试
  debug: false,

  get mini_assets() { return !this.debug; }, // 是否启用静态文件的合并压缩，详见视图中的Loader

  name: '最盟', // 俱乐部的名字
  description: '最盟: 上海高校运动联盟，以跑步为核心的跨校运动交流、分享平台，跑步信息发布、报名、志愿者招募，合作体育品牌和主办方的各种福利，结识上海十几所高校的跑者和NTCgirls，与全校已注册师生和校友一起互动、PK你的跑马成绩。最盟，不只运动，遇见感动！', // 俱乐部的的描述
  keywords: '最盟,最猛,最萌,高校,拉风,跑步,运动,同济',

  // 添加到 html head 中的信息
  site_headers: [
    '<meta name="author" content="johning" />'
  ],
  site_logo: '/public/images/myclub_light2.png', // default is `name`
  site_icon: '/public/images/cnode_icon_32.png', // 默认没有 favicon, 这里填写网址
  // 右上角的导航区
  site_navs: [
    // 格式 [ path, title, [target=''] ]
    [ '/about', '关于' ]
  ],
  // cdn host，如 http://cnodejs.qiniudn.com
  site_static_host: '', // 静态文件存储域名
  // 俱乐部的的域名
  host: 'localhost',
  // 默认的Google tracker ID，自有站点请修改，申请地址：http://www.google.com/analytics/
  google_tracker_id: '',
  // 默认的cnzz tracker ID，自有站点请修改
  cnzz_tracker_id: '',

  // mongodb 配置
  db: 'mongodb://127.0.0.1/node_club_dev',
  db_name: 'node_club_dev',

  // redis 配置，默认是本地
  redis_host: '127.0.0.1',
  redis_port: 6379,

  session_secret: 'club_test_secret', // 务必修改
  auth_cookie_name: 'club_test',
  auth_weixin_cookie_name: 'weixin',

  // 程序运行的端口
  port: 80,

  // 话题列表显示的话题数量
  list_topic_count: 20,

  // 微信的相关配置
  weixin: {
    authorizeUrl: 'https://open.weixin.qq.com/connect/oauth2/authorize',
    appid: 'wx35ee7d6d83988da7',
    secret: 'd74b37620ecaa50b8bc7d399c2eebe0f',
    redirectUri: 'http://m.zuimeng.org/signup'
  },



  // // RSS配置
  // rss: {
  //   title: 'CNode：Node.js专业中文俱乐部的',
  //   link: 'http://cnodejs.org',
  //   language: 'zh-cn',
  //   description: 'CNode：Node.js专业中文俱乐部的',
  //   // 最多获取的RSS Item数量
  //   max_rss_items: 50
  // },

  // 邮箱配置
  mail_opts: {
    host: 'smtp.163.com',
    port: 25,
    auth: {
      user: 'hjny11@163.com',
      pass: '253926gfdsA'
    }
  },

  //weibo app key
  weibo_key: 10000000,
  weibo_id: 'your_weibo_id',

  // admin 可删除话题，编辑标签，设某人为达人
  admins: { user_login_name: true },

  // github 登陆的配置
  GITHUB_OAUTH: {
    clientID: 'your GITHUB_CLIENT_ID',
    clientSecret: 'your GITHUB_CLIENT_SECRET',
    callbackURL: 'http://cnodejs.org/auth/github/callback'
  },
  // 是否允许直接注册（否则只能走 github 的方式）
  allow_sign_up: true,

  // newrelic 是个用来监控网站性能的服务
  newrelic_key: 'yourkey',

  // 下面两个配置都是文件上传的配置

  // 7牛的access信息，用于文件上传
  qn_access: {
    accessKey: 'qmD79qq2RUVO1-cfnOR5o8Y7v5UuEpre1pZwe5ah',
    secretKey: 'kR4NtM0QsCxZCAjk5e2_jwSJ328OMsmev1X8wdny',
    bucket: 'myclub',
    domain: 'http://7xijdk.com1.z0.glb.clouddn.com'
  },

  // 文件上传配置
  // 注：如果填写 qn_access，则会上传到 7牛，以下配置无效
  upload: {
    path: path.join(__dirname, 'public/upload/'),
    url: '/public/upload/'
  },

  // 版块
  tabs: [
    ['run', '跑步'],
    ['basketball', '篮球'],
    ['football', '足球'],
    ['badminton', '羽毛球'],
    ['others', '其他']
  ],

  // 极光推送
  jpush: {
    appKey: 'YourAccessKeyyyyyyyyyyyy',
    masterSecret: 'YourSecretKeyyyyyyyyyyyyy',
    isDebug: false,
  },

  create_post_per_day: 1000, // 每个用户一天可以发的主题数
  create_reply_per_day: 1000, // 每个用户一天可以发的评论数
  visit_per_day: 1000, // 每个 ip 每天能访问的次数
};

module.exports = config;