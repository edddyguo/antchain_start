// contracts/Market.sol
// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.6.4;
// pragma experimental ABIEncoderV2;


/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(identity indexed from, identity indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(identity indexed owner, identity indexed spender, uint256 value);

    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(identity account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(identity to, uint256 amount) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(identity owner, identity spender) external view returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(identity spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `from` to `to` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(
        identity from,
        identity to,
        uint256 amount
    ) external returns (bool);
}


interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
/**
 * @dev Required interface of an ERC721 compliant contract.
 */
interface IERC721 is IERC165 {
    /**
     * @dev Emitted when `tokenId` token is transfered from `from` to `to`.
     */
    event Transfer(identity indexed from, identity indexed to, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables `approved` to manage the `tokenId` token.
     */
    event Approval(identity indexed owner, identity indexed approved, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables or disables (`approved`) `operator` to manage all of its assets.
     */
    event ApprovalForAll(identity indexed owner, identity indexed operator, bool approved);

    /**
     * @dev Returns the number of tokens in ``owner``'s account.
     */
    function balanceOf(identity owner) external view returns (uint256 balance);

    /**
     * @dev Returns the owner of the `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function ownerOf(uint256 tokenId) external view returns (identity owner);

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * Requirements:
     *
     * - `from` cannot be the zero identity.
     * - `to` cannot be the zero identity.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must be have been allowed to move this token by either {approve} or {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(identity from, identity to, uint256 tokenId) external;

    /**
     * @dev Transfers `tokenId` token from `from` to `to`.
     *
     * WARNING: Usage of this method is discouraged, use {safeTransferFrom} whenever possible.
     *
     * Requirements:
     *
     * - `from` cannot be the zero identity.
     * - `to` cannot be the zero identity.
     * - `tokenId` token must be owned by `from`.
     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(identity from, identity to, uint256 tokenId) external;

    /**
     * @dev Gives permission to `to` to transfer `tokenId` token to another account.
     * The approval is cleared when the token is transferred.
     *
     * Only a single account can be approved at a time, so approving the zero identity clears previous approvals.
     *
     * Requirements:
     *
     * - The caller must own the token or be an approved operator.
     * - `tokenId` must exist.
     *
     * Emits an {Approval} event.
     */
    function approve(identity to, uint256 tokenId) external;

    /**
     * @dev Returns the account approved for `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function getApproved(uint256 tokenId) external view returns (identity operator);

    /**
     * @dev Approve or remove `operator` as an operator for the caller.
     * Operators can call {transferFrom} or {safeTransferFrom} for any token owned by the caller.
     *
     * Requirements:
     *
     * - The `operator` cannot be the caller.
     *
     * Emits an {ApprovalForAll} event.
     */
    function setApprovalForAll(identity operator, bool _approved) external;

    /**
     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.
     *
     * See {setApprovalForAll}
     */
    function isApprovedForAll(identity owner, identity operator) external view returns (bool);

    /**
      * @dev Safely transfers `tokenId` token from `from` to `to`.
      *
      * Requirements:
      *
     * - `from` cannot be the zero identity.
     * - `to` cannot be the zero identity.
      * - `tokenId` token must exist and be owned by `from`.
      * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
      * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
      *
      * Emits a {Transfer} event.
      */
    function safeTransferFrom(identity from, identity to, uint256 tokenId, bytes calldata data) external;
}

/**
 * @title SafeMath
 * @dev 安全的 uint256 数学基本计算
 */
library SafeMath {
    /**
     * @dev 乘法，若有溢出则revert
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");

        return c;
    }

    /**
     * @dev 除法，除0时 revert
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // Solidity only automatically asserts when dividing by 0
        require(b > 0, "SafeMath: division by zero");
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return c;
    }

    /**
     * @dev 减法
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath: subtraction overflow");
        uint256 c = a - b;

        return c;
    }

    /**
     * @dev 加法
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");

        return c;
    }

    /**
     * @dev 求余数，除数为0时 revert
     */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b != 0, "SafeMath: modulo by zero");
        return a % b;
    }
}


contract contractMarketPlace {

    using SafeMath for uint256;
    identity admin; // 合约管理员角色

    uint256 public _orderIdCounter = 0;
    uint256 public _indexCounter = 0;
    identity  public withdrawalidentity;  //提现地址
    uint256 public platformFee = 5; //平台手续费  100
    uint256 private ratio = 100;

    enum State{
        Created, Release, Inactive
    }

    struct Order {
        uint256 id;
        identity nftContract;
identity payable seller;
identity payable buyer;
uint256 assetId;
uint256 price;
State state;
uint256 expiresAt;
}


mapping(uint256 => Order) private orders;

event OrderCreated(uint256 indexed id, identity nftContract, identity  seller, identity  buyer, uint256 indexed assetId, uint256 price, State state, uint256 expiresAt);
event OrderSuccessful(uint256 indexed id, identity nftContract, identity  seller, identity  buyer, uint256 indexed assetId, uint256 price, State state);
event OrderCancelled(uint256 indexed id,identity nftContract, identity  seller, identity  buyer, uint256 indexed assetId, uint256 price, State state);
event ChangeWithdrawalidentity(identity withdrawalidentity);
event ChangePlatformFee(uint256 indexed platformFee);

modifier onlyAdmin(){
require(msg.sender == admin, "Permission denied");
_;
}


constructor(identity _withdrawalidentity, uint256 _platformFee) public{
admin = msg.sender;
setWithdrawalidentity(_withdrawalidentity);
setPlatformFee(_platformFee);
}


function setWithdrawalidentity(identity _withdrawal) public onlyAdmin{
withdrawalidentity = (_withdrawal);
emit ChangeWithdrawalidentity(_withdrawal);
}

function setPlatformFee(uint256 _platformFee) public onlyAdmin{
platformFee = _platformFee;
emit ChangePlatformFee(_platformFee);
}


function createOrder(identity payable _nftContract, uint256 _assetId,uint256 _price, uint _expiresAt)public  returns (uint256){

_orderIdCounter++;
uint256 orderId = _orderIdCounter;

orders[orderId] = Order({
id : orderId,
nftContract : _nftContract,
seller : msg.sender,
buyer : identity(0),
assetId : _assetId,
price : _price,
state : State.Created,
expiresAt : _expiresAt
});

emit OrderCreated(orderId, _nftContract, msg.sender, identity(0), _assetId,_price, State.Created, _expiresAt);
return orderId;
}


function executeOrder(identity _nftContract, uint256 _orderId, uint256 _price)public  returns (uint256){

Order storage order = orders[_orderId];
require(order.state == State.Created, "MarketPlace_executeOrder:order is Invalid");
require(order.seller != identity(0), "MarketPlace_executeOrder:Invalid seller");
require(order.seller != msg.sender, "MarketPlace_executeOrder:sender is seller");
require(block.timestamp < order.expiresAt, "MarketPlace_executeOrder:order expired");

require(_price >= order.price,"MarketPlace_executeOrder:invalid price");

order.state = State.Release;
order.buyer = (msg.sender);


emit OrderSuccessful(_orderId, _nftContract, order.seller, msg.sender, order.assetId,_price, State.Release);
return _orderId;
}


function cancelOrder(uint256 _orderId) public  returns (uint256 ){
Order storage order = orders[_orderId];
require(_orderId != 0, "MarketPlace_cancelOrder: INVALID_ORDER");
require(orders[_orderId].seller == msg.sender , "MarketPlace_cancelOrder:UNAUTHORIZED_USER");

order.state = State.Inactive;

emit OrderCancelled(_orderId, order.nftContract, order.seller, identity(0),order.assetId, order.price, State.Inactive);
return _orderId;
}


}