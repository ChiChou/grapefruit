export {};

declare global {
  interface Array<T> {
      includes(searchElement: T): boolean;
  }
}

if (!Array.prototype.includes) {
  Array.prototype.includes = function(searchElement: any, fromIndex?: number | undefined) : boolean {
    return this.indexOf(searchElement, fromIndex) > -1;
  }
}