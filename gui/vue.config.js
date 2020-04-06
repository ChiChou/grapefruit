module.exports = {
  devServer: {
    proxy: {
      '^/api': {
        target: 'http://localhost:31337/',
        ws: true,
        changeOrigin: true
      }
    }
  }
}