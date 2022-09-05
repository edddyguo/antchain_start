// SPDX-License-Identifier: MIT
pragma solidity ^0.6.4;

    contract fanchant {
        //======================variable======================
        //定义一个结构体 保存玩家当前游戏的结果信息
        struct player{
            uint256 role; //所选择的角色
            uint256 winScores; //玩家的得分
            uint256 level;        //玩家等级
            //玩家的开始时间
            uint256 startTime;
            //玩家的结束时间
            uint256 endTime;
        }

        //定义轮次
        uint256 public round;

        //每一轮 每一个玩家的详细数据 0-identity01-10
        mapping(uint256 => mapping(identity => player)) public roundPlayers;

        identity owner;

        //玩家的奖励制
        mapping(uint256 => uint256) public reward;

        //define 构造函数
        constructor() public {
            owner = msg.sender;
        }
        //======================event========================

        //======================modifier======================
        //定义一个modifier 用于判断是否是合约的拥有者
        modifier onlyOwner() {
            require(msg.sender == owner, "only owner can call this function");
            _;
        }



        //======================function======================
        //定义一个函数 用于玩家选择角色
        //0 角色1 玩家等级
        function chooseRole(uint256 round,uint256 _role,uint8 playerLevel) public {
            //判断玩家是否已经选择过角色
            require(roundPlayers[round][msg.sender].role == 0, "You have already chosen a role");
            //begin game
            //判断玩家选择的角色是否合法
            require(_role >= 1 && _role <= 8, "The role you choose is illegal");
            //判断玩家等级是否合法
            require(playerLevel >= 1 && playerLevel <= 10, "The level you choose is illegal");
            //record current information
            roundPlayers[round][msg.sender].role = _role;
            roundPlayers[round][msg.sender].level = playerLevel;
        }


    //define function 用于记录玩家的得分
    function recordScores(string memory player,uint256 _scores) onlyOwner public {

        //判断是否已经结束 结束-开始大于5分钟结束 游戏确实已经结束
        require(roundPlayers[round][msg.sender].endTime - roundPlayers[round][msg.sender].startTime > 5 minutes, "The game has not ended yet");
        //recordScores 用于记录玩家的得分
        roundPlayers[round][msg.sender].winScores = _scores;
    }
}
