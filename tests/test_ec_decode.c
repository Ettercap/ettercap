#include <stdio.h>
#include <check.h>

#include <ec.h>
#include <ec_libettercap.h>
#include <ec_decode.h>
#include <ec_proto.h>

struct ec_globals *ec_gbls;

// Yes, this is hack-ish. We can change it later.

START_TEST (test_get_decoder_default)
{
  fail_if(get_decoder(APP_LAYER, PL_DEFAULT) == NULL, "Could not find default decoder.");
}
END_TEST

START_TEST (test_get_decoder_ip)
{
  fail_if(get_decoder(NET_LAYER, LL_TYPE_IP) == NULL, "Could not find IP decoder.");
}
END_TEST

START_TEST (test_get_decoder_tcp)
{
  fail_if(get_decoder(PROTO_LAYER, NL_TYPE_TCP) == NULL, "Could not find TCP decoder.");
}
END_TEST

START_TEST (test_get_decoder_udp)
{
  fail_if(get_decoder(PROTO_LAYER, NL_TYPE_UDP) == NULL, "Could not find UDP decoder.");
}
END_TEST

Suite* ts_test_decode (void) {
  Suite *suite = suite_create("ts_test_decode");
  TCase *tcase = tcase_create("get_decoder");
  tcase_add_test(tcase, test_get_decoder_default);
  tcase_add_test(tcase, test_get_decoder_ip);
  tcase_add_test(tcase, test_get_decoder_tcp);
  tcase_add_test(tcase, test_get_decoder_udp);
  suite_add_tcase(suite, tcase);
  return suite;
}

int main () {
  int number_failed;
  libettercap_init("test", "0.0.1");
  Suite *suite = ts_test_decode();
  SRunner *runner = srunner_create(suite);
  srunner_run_all(runner, CK_VERBOSE);
  number_failed = srunner_ntests_failed(runner);
  srunner_free(runner);
  return number_failed;
}


