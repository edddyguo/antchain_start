pragma solidity <=0.6.4;

contract HelloV2 {

    string name;
    identity id; //identity 类似于原生 Solidity 语言的 address

    constructor() public {
        name = 'HelloV2------Hello world!';
    }

    function hello() view public returns (identity, string memory) {
        return (msg.sender, name);
    }

    //add test function
    function test()  public returns (string memory) {
        return 'test';
    }

}