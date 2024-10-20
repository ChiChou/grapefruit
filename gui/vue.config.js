const webpack = require('webpack')
const MonacoWebpackPlugin = require('monaco-editor-webpack-plugin')

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
      .use(new MonacoWebpackPlugin())
  },
  devServer: {
    host: 'localhost',
    allowedHosts: [
      '.local' // allow LAN
    ],
    proxy: {
      '^/(api|socket\.io)': {
        target: 'http://localhost:31337/',
        ws: true,
        changeOrigin: true
      }
    }
  }
}
