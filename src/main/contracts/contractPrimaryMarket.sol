// contracts/Market.sol
// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.4.23;

import "./contractMarket.sol";
pragma experimental ABIEncoderV2;
//issue one token
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

contract A is IERC20{
    function totalSupply() external view returns (uint256) {
        return 0;
    }

    function balanceOf(identity account) external view returns (uint256) {
        return 0;
    }

    function transfer(identity to, uint256 amount) external returns (bool) {
        return true;
    }

    function allowance(identity owner, identity spender) external view returns (uint256) {
        return 0;
    }

    function approve(identity spender, uint256 amount) external returns (bool) {
        return true;
    }

    function transferFrom(
        identity from,
        identity to,
        uint256 amount
    ) external returns (bool) {
        return true;
    }
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


//erc20 interdace
interface tokenInterface {
    function balanceOf(identity owner) external view returns (uint256);
    function transfer(identity to, uint256 value) external returns (bool) ;
    function allowance(identity owner, identity spender) external view returns (uint256) ;
    function issue(identity account, uint256 value) external returns (bool) ;
    function transferFrom(identity from, identity to, uint256 value) external returns (bool) ;
    function _transfer(identity from, identity to, uint256 value) external;
    function approve(identity spender, uint256 value) public returns (bool);
}

contract contractPrimaryMarket {
    identity admin;
    identity  supportedToken;
    uint256 public price ;

    event BuySuccessful(identity nftContract,identity seller,identity  buyer,uint256 indexed assetId,uint256 price);
    event ChangePrice(uint256 indexed price);

    modifier onlyAdmin(){
        require(msg.sender == admin,"Permission denied");
        _;
    }

    constructor(identity _acceptedToken,uint256 _price) public{
        admin = msg.sender;
        changePrice=_price;
        supportedToken = tokenInterface(_acceptedToken);
    }

    function changePrice(uint256 _price) public onlyAdmin{
        price = _price;
        emit ChangePrice(price);
    }

    function buy(identity  _nftContract, identity _seller ,identity _buyer,uint256 _assetId,uint256 _price)public  returns(uint256){
        require(_price >= price,"MarketPlace_createOrder:price should be bigger than 0");
        (bool success1)  = acceptedToken.transferFrom(_buyer,_seller,_price);
        require(success1,"contractPrimaryMarket:TRANSFER_PRICE_TO_SELLER_FAILED");

        (bool success2,bytes memory data2)  = _nftContract.call(abi.encodeWithSignature("transferFrom(identity,identity,uint256)",_seller,_buyer,_assetId));

        emit BuySuccessful(_nftContract,_seller,_buyer,_assetId,_price);
        return _assetId;
    }

    //test transfer
    function test_transfer(identity from,identity to,uint256 amount) public{
        // 1. 跨合约调用，需要通过合约 API 定义及合约 ID 生成一个合约对象
        supportedToken._transfer(from,to,amount);
    }
}