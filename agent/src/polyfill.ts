export {};

declare global {
  interface Array<T> {
    includes(searchElement: T): boolean;
  }

  interface String {
    matchAll(regexp: RegExp): IterableIterator<RegExpMatchArray>;
  }
}

if (!Array.prototype.includes) {
  Array.prototype.includes = function(searchElement: any, fromIndex?: number | undefined) : boolean {
    return this.indexOf(searchElement, fromIndex) > -1;
  }
}

if (!String.prototype.matchAll) {
  String.prototype.matchAll = function*(regex: RegExp): IterableIterator<RegExpMatchArray> {
    let match
    let index = 0
    let str
    while ((str = this.substr(index), match = regex.exec(str))) {
      str = this.substr(index)
      yield match
    }
  }
}
