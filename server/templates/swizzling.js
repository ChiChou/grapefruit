const method = ObjC.classes['{{ class }}']['{{ method }}'];
const original = method.implementation;
method.implementation = ObjC.implement(method, () => {
  // todo: add code here
});