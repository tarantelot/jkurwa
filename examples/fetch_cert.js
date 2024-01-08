var Box = require('../lib/app/ctx');
var gost89 = require('gost89');
const fs = require("fs");

var {fetch, getUserInfo} = require('../lib/util/fetch_certificates')


function getKeyBox(keyPath, keyPassword){
    try{
        return new Box({
            keys: [{
                file: keyPath,
                password: keyPassword,
            }],
            algo: gost89.compat.algos()
        });
    }catch(error){
        console.log('some error')
        return error
    }
}

function getPubKeyId(privKey, algo){
    return privKey.pub().keyid(algo)

    // var keyids = box.keys.map(function (info) {
    //     return info.priv.pub().keyid(box.algo);
    // });
}

function main(){
    // const keyPath     = "D:/projects/mistokasa_core_async/user_data/owner_2958411795/cashier_2958411795/sign_keys/stamp_vodomat.ZS2"
    // const keyPassword = '2958411795'

    const keyPath     = "D:/downloads/Key-6.dat_"
    const keyPassword = 'Nk123456_'


    // const keyPath     = "D:/projects/mistokasa_core_async/user_data/owner_2272714854/cashier_2272714854/sign_keys/Key-6.dat"
    // const keyPassword = '2272714854'

    // var b = fs.readFileSync(`./test/data/Key-6.dat`)

    // var box = getKeyBox(bb, keyPassword)

    // var keyOne = box.keys[0]
    // console.log(`Key one file: ${keyOne.priv}`)

    // var keyOnePub = keyOne.priv.pub().point
    // console.log(`KeyOne point: ${keyOnePub}`)
    
    // var keyOnePub = keyOne.priv.pub().curve
    // console.log(`KeyOne curve: ${keyOnePub}`)
    
    // var keyOneId = keyOne.priv.pub().keyid(box.algo)
    // console.log(`KeyOne id: ${keyOneId}`)


    var res = getUserInfo(keyPath, keyPassword)
    console.log(`res: ${res}`)

    res.then(result => {
        result[0].forEach((element, i) => {
            const cert_data = JSON.stringify(element.dict, null, 2)
            console.log(`element: ${cert_data}`)
            // fs.writeFileSync(`D:/projects/jkurwa_test/jkurwa/test/cert_${i}.cer`, element.raw);
        });

        
    })
}


main()