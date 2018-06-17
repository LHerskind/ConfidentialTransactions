pragma solidity ^0.4.19;
pragma experimental ABIEncoderV2;

library alt_bn128 {

    uint256 public constant q = 21888242871839275222246405745257275088548364400416034343698204186575808495617; // curve order
    uint256 public constant n = 21888242871839275222246405745257275088696311157297823662689037894645226208583; // prime field order
    
    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    function add(G1Point p1, G1Point p2) internal view returns (G1Point r) {
        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        assembly {
            if iszero(staticcall(not(0), 6, input, 0x80, r, 0x40)) {
                revert(0, 0)
            }
        }
    }

    function mul(G1Point p, uint256 s) internal view returns (G1Point r) {
        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        assembly {
            if iszero(staticcall(not(0), 7, input, 0x60, r, 0x40)) {
                revert(0, 0)
            }
        }
    }

    function neg(G1Point p) internal returns (G1Point) {
        // uint n = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, n - (p.Y % n));
    }

    function eq(G1Point p1, G1Point p2) internal pure returns (bool) {
        return p1.X == p2.X && p1.Y == p2.Y;
    }

    function add(uint256 x, uint256 y) internal pure returns (uint256) {
        return addmod(x, y, q);
    }

    function mul(uint256 x, uint256 y) internal pure returns (uint256) {
        return mulmod(x, y, q);
    }

    function inv(uint256 x) internal view returns (uint256) {
        return exp(x, q - 2);
    }

    function mod(uint256 x) internal pure returns (uint256) {
        return x % q;
    }

    function sub(uint256 x, uint256 y) internal pure returns (uint256) {
        return x >= y ? x - y : q - y + x;
    }

    function neg(uint256 x) internal pure returns (uint256) {
        return q - x;
    }

    function exp(uint256 base, uint256 exponent) internal view returns (uint256) {
        uint256[6] memory input;
        uint256[1] memory output;
        input[0] = 0x20;  // length_of_BASE
        input[1] = 0x20;  // length_of_EXPONENT
        input[2] = 0x20;  // length_of_MODULUS
        input[3] = base;
        input[4] = exponent;
        input[5] = q;
        assembly {
            if iszero(staticcall(not(0), 5, input, 0xc0, output, 0x20)) {
                revert(0, 0)
            }
        }
        return output[0];
    }
}
contract Owned {
    address public owner;
    address public newOwner;

    event OwnershipTransferred(address indexed _from, address indexed _to);
        
    function Owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
 
    function transferOwnership(address _newOwner) public onlyOwner {
        newOwner = _newOwner;
    }

    function acceptOwnership() public {
        require(msg.sender == newOwner);
        owner = newOwner;
        newOwner = address(0);
        OwnershipTransferred(owner, newOwner);
    }
}

contract KnowledgeProofVerifier{
    function verify(uint256[8] coords) public view returns(bool);
}

// Verifying one at a time. Not batched
contract RangeProofVerifier{
    function verify(uint256[10] coords, uint256[5] scalars, uint256[4] ls_coords, uint256[4] rs_coords) public view returns(bool);
}

contract BulletCoin is Owned {
    using alt_bn128 for uint256;
    using alt_bn128 for alt_bn128.G1Point;
    
    string public symbol;
    string public name;

    address public knowledgeProofVerifierAddress;
    address public rangeProofVerifierAddress;

    uint public n = 2;
    mapping(address => alt_bn128.G1Point) balances;
    mapping(address => mapping(address =>alt_bn128.G1Point)) pendingTransactions;

    event Transfer(address indexed _from, address indexed _to, uint X, uint Y);
    event Receive(address indexed _from, address indexed _to, uint X, uint Y);
    event Mint(address indexed _from, address indexed _to, uint X, uint Y);

    function BulletCoin(string _symbol, string _name, address _knowledgeProofVerifierAddress, address _rangeproofVerifierAddress) public{
        symbol = _symbol;
        name = _name;
        knowledgeProofVerifierAddress = _knowledgeProofVerifierAddress;
        rangeProofVerifierAddress = _rangeproofVerifierAddress;
    }

    function getXOfCommitBalance(address _user) public constant returns(uint256){
        return balances[_user].X;
    }
    
    function getYOfCommitBalance(address _user) public constant returns(uint256){
        return balances[_user].Y;
    }
    
    function transfer(address _to, uint256[20] coords, uint256[10] scalars, uint256[8] ls_coords, uint256[8] rs_coords) external returns(bool){
        address to = address(_to);
        
        require(pendingTransactions[msg.sender][to].eq(alt_bn128.G1Point(0,0)));
        
        alt_bn128.G1Point memory transferAmount = alt_bn128.G1Point(coords[0], coords[1]);
        alt_bn128.G1Point memory endBalance = alt_bn128.G1Point(coords[10], coords[11]);
        
        require(endBalance.eq(balances[msg.sender].add(transferAmount.neg())));
        
        uint256[10] memory coordsTemp;
        uint256[5] memory scalarsTemp;
        uint256[4] memory lstemp;
        uint256[4] memory rstemp;
        
        for(uint8 i = 0 ; i < 2; i++){
            uint8 j = 0;
            for(j = 0; j < coordsTemp.length; j++){
                coordsTemp[j] = coords[i*10+j];
            }
            for(j = 0; j < scalarsTemp.length;j++){
                scalarsTemp[j] = scalars[i*5+j];
            }
            for(j = 0; j < lstemp.length; j++){
                lstemp[j] = ls_coords[i*4+j];
                rstemp[j] = rs_coords[i*4+j];
            }
            require(RangeProofVerifier(rangeProofVerifierAddress).verify(coordsTemp, scalarsTemp, lstemp, rstemp));
        }

        balances[msg.sender] = endBalance;
        pendingTransactions[msg.sender][to] = transferAmount;
        emit Transfer(msg.sender, to, transferAmount.X, transferAmount.Y);
    }

    function recieve(address _from, uint256[6] coords) public returns(bool){
        require(!pendingTransactions[_from][msg.sender].eq(alt_bn128.G1Point(0,0)));
        alt_bn128.G1Point memory endBalance = balances[msg.sender].add(pendingTransactions[_from][msg.sender]);

        uint256[8] memory passOn;
        passOn[0] = endBalance.X;
        passOn[1] = endBalance.Y;
        uint8 j;
        for(j = 0; j < 6; j++){
            passOn[j+2] = coords[j];
        }
        require(KnowledgeProofVerifier(knowledgeProofVerifierAddress).verify(passOn));
        uint256 X = pendingTransactions[_from][msg.sender].X;
        uint256 Y = pendingTransactions[_from][msg.sender].Y;
        pendingTransactions[_from][msg.sender] = alt_bn128.G1Point(0,0);
        balances[msg.sender] = endBalance;
        emit Receive(_from, msg.sender, X, Y);       
    }

    function mint(address _to, uint256 _x, uint256 _y) onlyOwner public returns(bool){
        require(pendingTransactions[msg.sender][_to].eq(alt_bn128.G1Point(0,0)));
        alt_bn128.G1Point memory transferAmount = alt_bn128.G1Point(_x, _y);
        pendingTransactions[msg.sender][_to] = transferAmount;
        emit Mint(msg.sender, _to, transferAmount.X, transferAmount.Y);       
    }

    function () public payable{
        revert();
    }

}