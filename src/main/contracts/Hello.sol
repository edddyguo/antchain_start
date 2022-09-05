pragma solidity 0.6.4;

contract Hello {

    string name;
    identity id; //identity 类似于原生 Solidity 语言的 address

    constructor() public {
        name = 'Hello world!';
    }

    function hello() public view returns (identity) {
        return (msg.sender);
    }
}