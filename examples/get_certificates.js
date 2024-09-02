const {getUserInfo} = require('../lib/util/fetch_certificates')


function main(){
    // const keyPath     = ""
    // const keyPassword = ''

    // const keyPath     = ""
    // const keyPassword = ''

    // const keyPath     = process.argv[2]
    // const keyPassword = process.argv[3]

    try{
        var res = getUserInfo(keyPath, keyPassword)

        var response = []
        res.then(result => {
            result[0].forEach((element, i) => {
                // const cert_data = JSON.stringify(element)
                const cert_data = element
        
                response.push(cert_data)
                // fs.writeFileSync(`D:/projects/jkurwa_test/jkurwa/test/cert_${i}.cer`, element.raw);
            });
            response = JSON.stringify(response, null, 0)

            console.log(`data: ${response}`)
        })
    } catch(error){
        const to_return = {'msg': error.message}
        var response = JSON.stringify(to_return, null, 0)

        console.error(`error: ${response}`)
    }
}


main()
