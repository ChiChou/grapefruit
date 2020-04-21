const webpack = require('webpack')

module.exports = {
  chainWebpack: config => {
    config
      .plugin('provide')
      .use(new webpack.ProvidePlugin({
        $: 'jquery',
        jQuery: 'jquery',
        JQuery: 'jquery',
        'window.jQuery': 'jquery'
      }))
  },
  devServer: {
    proxy: {
      '^/(api|socket\.io)': {
        target: 'http://localhost:31337/',
        ws: true,
        changeOrigin: true
      }
    }
  }
}