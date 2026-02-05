#include <parm.h>

void run()
{
  BEGIN();

  int a, b, c, d;
  a = 12;
  b = 30;
  c = a + b;   // 42
  d = c - 2;   // 40

  // boucle infinie pour “rester” en exécution
  while (1) { }

  END();
}