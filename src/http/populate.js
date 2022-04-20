// populates missing values
const populate = function(dst, src) {

    Object.keys(src).forEach(function(prop)
    {
      dst[prop] = dst[prop] || src[prop];
    });
  
    return dst;
  };
  
export {
  populate
};
