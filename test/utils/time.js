function getCurrentTime() { 
    return new Promise(function(resolve) { 
        web3.eth.getBlock("latest").then(function(block) { 
            resolve(block.timestamp) 
        });
    }) 
}

Object.assign(exports, { 
    getCurrentTime 
});