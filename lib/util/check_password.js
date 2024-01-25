var Box = require('../app/ctx');
var gost89 = require('gost89');



async function fileToBuffer(file){
    return new Promise((resolve, reject) => {
        const reader = new FileReader();

        reader.onload = (event) => {
            const arrayBuffer = event.target.result;
            const buffer = Buffer.from(arrayBuffer);
            resolve(buffer);
        };

        reader.onerror = (error) => {
            reject(error);
        };

        reader.readAsArrayBuffer(file);
    });
}


function isPasswordCorrect(signKeyFile, password){
    fileToBuffer(signKeyFile)
    .then(buffer => {
        var u = new Uint8Array(buffer)
        var fileBuf = Buffer.from(u, 'hex')

        new Box({
            keys: [{
                file: fileBuf,
                password: password,
            }],
            algo: gost89.compat.algos()
        });

        return true
    })
    .catch(error => {
        return false
    });
   
}


module.exports.isPasswordCorrect = isPasswordCorrect;