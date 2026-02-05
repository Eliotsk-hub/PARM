#include <parm.h>

void run()
{
  BEGIN();

  int i, sum;
  sum = 0;

  for (i = 0; i < 10; i = i + 1) {
    sum = sum + i;   // résultat attendu: 0+1+...+9 = 45
  }

  while (1) { }

  END();
}