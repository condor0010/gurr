
void functionFive();

void functionOne() {
    functionTwo();
}

void functionTwo() {
    functionThree();
}

void functionThree() {
    functionFour();
}

void functionFour() {
    functionFive();
}

void functionFive() {
  asm("nop");
}

int main() {
    functionOne();
    return 0;
}

