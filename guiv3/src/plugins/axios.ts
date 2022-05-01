import axios from 'axios';

const instance = axios.create({
  baseURL: '/api'
});

instance.interceptors.request.use(
  response => response,
  error => {
    // Snackbar.open({
    //   type: 'is-warning',
    //   queue: false,
    //   message: error.response.data,
    //   actionText: 'Dismiss'
    // })
    return Promise.reject(error)
  });

export default instance;