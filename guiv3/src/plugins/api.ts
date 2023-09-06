export async function get<T>(input: URL | RequestInfo, init?: RequestInit) {
  return request<T>(input, init)
}

export async function post<T>(input: URL | RequestInfo, init?: RequestInit) {
  return request<T>(input, { method: 'POST', ...init })
}

export async function put<T>(input: URL | RequestInfo, init?: RequestInit) {
  return request<T>(input, { method: 'PUT', ...init })
}

export async function request<T>(input: URL | RequestInfo, init?: RequestInit) {
  let pathname = '/api'

  if (typeof input === 'string') {
    pathname += input
  } else if (input instanceof URL) {
    pathname += input.pathname
  }

  const url = new URL(pathname, location.href)
  return fetch(url, init).then(res => res.json() as Promise<T>)
}
