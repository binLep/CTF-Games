去年 Z 同学在赛后认真研发并推出了基于 CRC32 工作量证明的 CRC32 coin，但上线不到 2 分钟就被哈希碰撞攻击，后因多个严重的安全问题而被迫终止。Z 同学心想，既然自己实现的区块链不安全，那么在现有的区块链上使用智能合约应该不会再有安全问题了吧。于是，Z 同学在 ETH 的测试链上发布了一个智能合约，实现了类似银行的功能，大家可以在里面安全地存储代币，谁也不可能把别人的代币取走。除此之外，Z 同学还在智能合约里面存储了一个你绝对猜不出来的神秘数字（flag1）。<br>
Z 同学还说，如果你支持他的项目，在合约中存储 1000000000000 个代币，就可以给你另一个 flag2 作为感谢。<br>
<a href="https://kovan.etherscan.io/address/0xe575c9abd35fa94f1949f7d559056bb66fddeb51">查看智能合约</a>
**补充说明**<br>
如果上面链接无法访问，请阅读以下补充信息，不影响解题：<br>
以太坊 Kovan 测试链，合约地址：0xE575c9abD35Fa94F1949f7d559056bB66FddEB51<br>
合约源代码：<br>
>
```cpp
pragma solidity ^0.4.26;

contract JCBank {
    mapping (address => uint) public balance;
    mapping (uint => bool) public got_flag;
    uint128 secret;

    constructor (uint128 init_secret) public {
        secret = init_secret;
    }

    function deposit() public payable {
        balance[msg.sender] += msg.value;
    }

    function withdraw(uint amount) public {
        require(balance[msg.sender] >= amount);
        msg.sender.call.value(amount)();
        balance[msg.sender] -= amount;
    }

    function get_flag_1(uint128 guess) public view returns(string) {
        require(guess == secret);

        bytes memory h = new bytes(32);
        for (uint i = 0; i < 32; i++) {
            uint b = (secret >> (4 * i)) & 0xF;
            if (b < 10) {
                h[31 - i] = byte(b + 48);
            } else {
                h[31 - i] = byte(b + 87);
            }
        }
        return string(abi.encodePacked("flag{", h, "}"));
    }

    function get_flag_2(uint user_id) public {
        require(balance[msg.sender] > 1000000000000 ether);
        got_flag[user_id] = true;
        balance[msg.sender] = 0;
    }
}
```