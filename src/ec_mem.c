/*
    ettercap -- global variables handling module

    Copyright (C) Ettercap Development Team

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

*/

#include <ec.h>

void safe_free_mem(char **param, int *param_length, char *command)
{
   int k;

   SAFE_FREE(command);
        for(k= 0; k < (*param_length); ++k)
                SAFE_FREE(param[k]);
        SAFE_FREE(param);
}








/* EOF */

// vim:ts=3:expandtab

