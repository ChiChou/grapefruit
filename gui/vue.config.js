module.exports = {
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