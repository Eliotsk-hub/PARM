#include <parm.h>

void run()
{
  BEGIN();

  int x, y, z;
  x = 7;
  y = 10;

  if (x < y) {
    z = 111;
  } else {
    z = 222;
  }

  while (1) { }

  END();
}