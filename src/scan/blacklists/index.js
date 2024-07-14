const mw = require('./malwareworld.js')


console.log("hello world")


mw.isMalicious("70.32.94.216").then(function(result){ 
        console.log(result);
    }, function(err) {
        console.log(err);
});


console.log(mw.getMalDomainsList())

console.log(mw.getGeneralStatistics())