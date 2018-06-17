
# Confidential transfers on Ethereum - the *bulletcoin*

This repository is the implementation of publicly verifiable confidential transfers on the Ethereum blockchain, as proposed in the BitFlow Paper.

The implementation builds on the foundation provided by BANKEX[2] and extends further upon the *"transfer protocol"*.

The implementation heavily depends upon homomorphic commitments: 
```
commitment(a+b, lambda_1+lambda_2) = commitment(a, lambda_1) + commitment(b, lambda_2)
```


To enable confidential transfers, we shall follow a rather short transfer protocol. 
This protocol will split public transfers into a *sending* and *receiving* part.
#### Transfer protocol
##### Sending
* Calculate and prove knowledge of `commitment(remaining_balance)`
* Prove that `remaining_balance >= 0 && amount_transferred >= 0`
* Share knowledge of amount to receiver, in a confidential manner

##### Receiving
* Calculate and prove knowledge of `commitment(new_balance)`

#### How to enable this
To prove that commitments are to non-negative values, we use the `Bulletproofs`[1]. 
More simple zero knowledge proofs will be used to proof knowledge of value x.

## How to use
To use the *bulletcoin* one have to provide a large set of arguments when initializing the *contracts*. 
To generate those arguments, goto the "Setup of *bulletcoin*".

### Setup the *bulletcoin*
Go to `Main_Testing.java` set `setupPhaes = true;`. When run, the output will be similar to:
```
Bitlength: 4
Setup phase
Ethereum input, knowledgeProofVerifier:
Bitlength: 4
Setup phase
Ethereum input, knowledgeProofVerifier:
["0x77da99d806abd13c9f15ece5398525119d11e11e9836b2ee7d23f6159ad87d4","0x1485efa927f2ad41bff567eec88f32fb0a0f706588b4e41a8d587d008b7f875", "0x1b7de3dcf359928dd19f643d54dc487478b68a5b2634f9f1903c9fb78331aef","0x2bda7d3ae6a557c716477c108be0d0f94abc6c4dc6b1bd93caccbcceaaa71d6b"]
Ethereum input, efficientInnerProductVerifier:
"0x1b7de3dcf359928dd19f643d54dc487478b68a5b2634f9f1903c9fb78331aef","0x2bda7d3ae6a557c716477c108be0d0f94abc6c4dc6b1bd93caccbcceaaa71d6b", ["0x2ee9d9ac7c3c8401799229d12a921be0a53a94e947b8fe4ad53c10271589475b", "0x519108633851fe30b4838cfaf87125ccab8d4b69ec3252ac1602e616e3a2153", "0x1a7a1daa878528015634237a65af5f902873b7aa5fffc5f64f00441974c14129", "0x2e2b1907c64b9e626f32e410528ba56b48087924f4128945d124ca30fddf948f", "0x27e30be9524ec86fa23ffd86df08f7534f873cfcd1c476acb06932f45e4b1aa3", "0x8874631f1dab5acd3ba1c7515ff8602a8a29d780a92ccb75ba4987d92343d75", "0x2d0947dd3b29da4c51c78592a8387970129d032e1780ebf81cd6402da3442287", "0x26ef630599deb3daad07d89a03128e344718ddb2b1341cbbc7d8ffee1ac82a90"], ["0x5b15e337abcece819885de2ed3156ffcabec15a950f964404243ac3fcc3bf14", "0x1e0c2181124139d3b10b3436a2aadb998567c855a1920e292c3fe5290aac5537", "0x16f3670892d79397118ab8f467b23bc27bfe18a415d6469166bfe95297dff6f0", "0x155c660440de206b6b7850d67b6a6c4490786607d3498e8d383a30372107d99e", "0x113704c3c34b857f7597bc982ed9ca82ea0f3abf9806b8da6d72c18552e7d308", "0x2c08ff1c34e9d097078a21114dd95427c05cd65974acf48334669ce4bb8daa96", "0x443cc7b905c13a74aba6df98c91127194586bf8d06713451d5921a944147f4", "0x2aed26812bc8cde8afa8d42e15adddb5890fa84f6994e0e5d8a368a0c1f8d140"]
Ethereum input, rangeProofVerifier:
["0x77da99d806abd13c9f15ece5398525119d11e11e9836b2ee7d23f6159ad87d4","0x1485efa927f2ad41bff567eec88f32fb0a0f706588b4e41a8d587d008b7f875", "0x1b7de3dcf359928dd19f643d54dc487478b68a5b2634f9f1903c9fb78331aef","0x2bda7d3ae6a557c716477c108be0d0f94abc6c4dc6b1bd93caccbcceaaa71d6b"], ["0x2ee9d9ac7c3c8401799229d12a921be0a53a94e947b8fe4ad53c10271589475b", "0x519108633851fe30b4838cfaf87125ccab8d4b69ec3252ac1602e616e3a2153", "0x1a7a1daa878528015634237a65af5f902873b7aa5fffc5f64f00441974c14129", "0x2e2b1907c64b9e626f32e410528ba56b48087924f4128945d124ca30fddf948f", "0x27e30be9524ec86fa23ffd86df08f7534f873cfcd1c476acb06932f45e4b1aa3", "0x8874631f1dab5acd3ba1c7515ff8602a8a29d780a92ccb75ba4987d92343d75", "0x2d0947dd3b29da4c51c78592a8387970129d032e1780ebf81cd6402da3442287", "0x26ef630599deb3daad07d89a03128e344718ddb2b1341cbbc7d8ffee1ac82a90"], ["0x5b15e337abcece819885de2ed3156ffcabec15a950f964404243ac3fcc3bf14", "0x1e0c2181124139d3b10b3436a2aadb998567c855a1920e292c3fe5290aac5537", "0x16f3670892d79397118ab8f467b23bc27bfe18a415d6469166bfe95297dff6f0", "0x155c660440de206b6b7850d67b6a6c4490786607d3498e8d383a30372107d99e", "0x113704c3c34b857f7597bc982ed9ca82ea0f3abf9806b8da6d72c18552e7d308", "0x2c08ff1c34e9d097078a21114dd95427c05cd65974acf48334669ce4bb8daa96", "0x443cc7b905c13a74aba6df98c91127194586bf8d06713451d5921a944147f4", "0x2aed26812bc8cde8afa8d42e15adddb5890fa84f6994e0e5d8a368a0c1f8d140"], ipVerifier
```
The ouputs provided, will be the list of arguments for initialization of the *contracts*. *"ipVerifier"* is contract of the *efficientInnerProductVerifier*.

### Testing the coin
An example of a possible usage of the coin, is made in `mint_then_transfer_and_receive` and will follow the flow:
* Init 2 users and their lambda.
* Mint 5 coins to *user1*
* *user1* receive the 5 tokens
* *user1* send 3 tokens to *user2*
* *user2* receive the 3 tokens

To execute this flow, simply set `setupPhase = false;` The ouput will then be as follows:
```
Bitlength: 4
Mint-commitment:
"0x22f0d6ec48adf22874a831a34703b8cc37b90a8f0de7ad79bc53b45c0cf12fcb","0x2edb129868ec0833acbcf522e6528f826228265a4bad09f9965900271296ded5"
KnowledgeProofVerifier inputs, from proof
["0x22f0d6ec48adf22874a831a34703b8cc37b90a8f0de7ad79bc53b45c0cf12fcb","0x2edb129868ec0833acbcf522e6528f826228265a4bad09f9965900271296ded5","0x27f7428e22403402c4a87e8fea81f65acf438f772ec372d33860a12ad9b69090","0xceee029a8744fbd6ee54c2a08065d20c61d73dab28df149121748eeba26f41","0x2c8a045d4214d27b60413d494369889f7ee34c781ba4e2ae615650a3d657f9d4","0x92c1bc926acf7702df979af361dbf7aa976c30e0d8965b5b86e28047ed4ba60"]
DoubleRangeProofVerifier inputs, from commitments and proofs
["0x224db7b86aa0f95e191a9c06ec242e044e42ad60b47a0c53f425a4d4b10dae2d","0x1ca7883b4d0211f7fe779c106ba0b3f2afd815a85b99f3ffa01c156aa31515c3", "0x2f100d08528249e66608001de913453b9892258ead0da83847917440817cf166","0xad57cf17d797bd5804eda44ec14f48d76cb73a6ea6c1c40690ff9aaa0dfa5f6", "0x26e067296947a25a6889e175cf82672632b483d935594b99f4d4db4b7153a92d","0x124f870482c02e74f3f5df542ef0b0655338e6ca3eeae39889b2c4124537fa34", "0x1f2c3da04a391312fa426b967addbf5b38a59aeb21e944e61e1ee6021c0f64da","0x110bfdfd8fa3708463d8af16a0b74aa80554d8069f5cf5d71c524f4c7d50c047", "0x2c8bca25a32f4ba069af8532b459df65fa1988349cbe2679bd6b7ff88c216283","0x1f842543a58179259c63bc8c16ea603e25c40bd0a93ebc7736134a07031236f", "0xf9cf54bca06d66cc30b2450f874a3c4a76b59d8490c269eef1fa4184dc341","0x302281bc04bb0c1bee12424c63315a1f951f804c6b8281802dc4cb045e4e2d36", "0x2ea15cd3683f91d0b1d98349d97ed2127f77cfb2e6207b7793c093a51c898401","0x33e0dd30db7adfeab0f23c60071d34ec133b13cb30da913ed24cf0142d0edba", "0x2df1a64f14c80f0fdaa4e701c8046e087f608fd5933619f27c23b3e6588f72da","0x50c1da02ce1f34bb134d76ea89b59ee6c7d0322e4fb2f5dd8c2db7af11f0f37", "0x83d9ad4c5d0d93f234714f896f9b1a1c1d0d640533e5b34fa97aa20698204cf","0x10f0bdf600184e7657443d3aa72e9d9be8e5761540daf8fb3db03eda8a1cb2d2", "0xbd59ab4e774c57f62b82d2ebed5e1f48daba119ebe889b58355f75d3fe6806d","0xf32e2a16389234ea726b5e70052ccc30ddb2e3387ddd79d68898fd744cd1ad"], ["0x1bc85a145e1e17da17af9eee76a84a3821aee716f9906a355009b44256aec4b8", "0x21535a4502470132f594771a55043c5a41f6ad324381e3019db1b8f7a6ad2f8a", "0xc87752acd87fd9846a414517925d6f2b975c292af71eef61be7f8c69f90446f", "0xeea9baa8ee9dc30cab9bdbd775c2d59c97c659de0d534045b569264686a946f", "0x1aa20eacec256b31543ea114b7f4adc4fd2185d3aeabed9f32cbdd70e4a5b1b0", "0x1e67f7eaac5e7bf221300f0d25becceef286fc74e403433842fad4d29e74f0fe", "0x7f06bfc092a0dc36ce261a6798180d0947591f31361515cd55652c8208b6e08", "0x2663564c3477fa56ca1a19877254fbd16f74e2d693bd2778a564b729f3c31d7e", "0x2ddbf7623e655072f27cfae4e8e12cb395563145bbc4f703cbd4c394af342980", "0x2faccf0a5abb07d4fdd5bdc4efe97e070b6b63df1c3bd7c8ec633fe81f96c8f6"], ["0x83fba8185755789efa17f802b337d34c6fd53a7b5162409492cf6fb3a5c3dcb", "0x107341823e1ccbda813bae25fe2c1ecc03fa4aba73c776ccd83b7084ea17eef0", "0x246f8eecad8613b252afbfe7d2e5de806ddbe5fa327ab44b9f27dfa9e9dfbb7f", "0x3f609844ed94f35f0752169d2ed548684c09362a3e2b828296e1b1929586c89", "0x1d8710fa747f1b336af6edae20c74b5a41e9b0ff903e34b30971647ac0369e3", "0x8dc8809675377f062445b9b53eb21770d1f21c77d83550b0cfb87f5feda1d1f", "0xde96e8241371fce8ca96a714627d9f5c6d08eed51b9ffd8faf23df6eaea924f", "0x23e005ede950acf5aa6f2e5f1adde8f5b5a5ad9d53ec2f1945b8326f5fd9fc33"], ["0x1a463e9885be3592340f1ca4b8f969ff0a3b45659ccd8d44b714b6a9bddeb747", "0xb842c9137fe35a4d2d697b9945b52f07637cdc3f0f2c71eb845c378eec4078e", "0x22f6960a9f578fe21af84bf799ccc6922c70f9664bf0fe8446038928f53b12c2", "0x18d36bd90270c730e38c7eb8d252cfe6b3ecf081476a674fea181031a8151f17", "0x5b6e34cf884d0ef2e13b63eb864461cb209b60cc9049702caeb8afb5b06dea1", "0x1217171fe90fbd0d2c601bc46892038c82fb49222f9a9bf860deeed27f832af5", "0x1ed6d8b504b228f4b7f0852552d56a380d24533c0e336dfce62b815d6103c3f3", "0x64a86026c6ce367e30b0c8d1c7e1c95e2145a9362b70c002dbfe81fafe31671"]
KnowledgeProofVerifier inputs, from proof
["0x224db7b86aa0f95e191a9c06ec242e044e42ad60b47a0c53f425a4d4b10dae2d","0x1ca7883b4d0211f7fe779c106ba0b3f2afd815a85b99f3ffa01c156aa31515c3","0x2bcd9056d6cd7b762f58232714a7ea843cea85e643d863f89d7b3b18ec0ba534","0x1f05bb52a0416f552b111f4e84e2b7aaf15046155877a9f44a258a926468c6af","0x1e2b04d6ff037ca9740e2428383da806752790225a46e86713c352fc16af9030","0x25f0062a8daef9dcceec66ee4d6585c7e3852caa210d061162342675b2082108"]
```
This is again just the arguments needed for the methods. Running the *minting* would be explicitly performed as:
```
bulletCoin.mint(<address_of_user_1>, "0x22f0d6ec48adf22874a831a34703b8cc37b90a8f0de7ad79bc53b45c0cf12fcb","0x2edb129868ec0833acbcf522e6528f826228265a4bad09f9965900271296ded5",{from:<owner_of_coin>});
```

[1]: https://crypto.stanford.edu/bulletproofs/
[2]: https://github.com/BANKEX/ETHDenver_ConfidentialTransactions
