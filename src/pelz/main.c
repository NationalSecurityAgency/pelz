/*
 * Contains the main function used to launch the Pelz Key Service
 */

#include <stdlib.h>

#include "key_table.h"
#include "pelz_service.h"
#include "pelz_log.h"

//Main function for the Pelz Service application
int main(int argc, char **argv)
{
  const int max_requests = 100;

  set_app_name("pelz");
  set_app_version("0.0.0");
  set_applog_path("/var/log/pelz.log");
  set_applog_severity_threshold(LOG_WARNING);

  //Initializing Key Table with max key entries set to key_max
  if (key_table_init())
  {
    pelz_log(LOG_ERR, "Key Table Init Failure");
    return (1);
  }

  pelz_service(max_requests);
  key_table_destroy();
  return (0);
}
