#include <stdio.h>
#include <check.h>

#include <ec.h>
#include <ec_decode.h>
#include <ec_proto.h>

// Yes, this is hack-ish. We can change it later.
FUNC_DECODER(decode_data);
FUNC_DECODER(decode_ip);
FUNC_DECODER(decode_tcp);
FUNC_DECODER(decode_udp);

START_TEST (test_get_decoder_default)
{
  fail_if(get_decoder(APP_LAYER, PL_DEFAULT) != (void*) decode_data, "Could not find default decoder.");
}
END_TEST

START_TEST (test_get_decoder_ip)
{
  fail_if(get_decoder(NET_LAYER, LL_TYPE_IP) != (void*) decode_ip, "Could not find IP decoder.");
}
END_TEST

START_TEST (test_get_decoder_tcp)
{
  fail_if(get_decoder(PROTO_LAYER, NL_TYPE_TCP) != (void*) decode_tcp, "Could not find TCP decoder.");
}
END_TEST

START_TEST (test_get_decoder_udp)
{
  fail_if(get_decoder(PROTO_LAYER, NL_TYPE_UDP) != (void*) decode_udp, "Could not find UDP decoder.");
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

int main (int argc, char *argv[]) {
  int number_failed;
  Suite *suite = ts_test_decode();
  SRunner *runner = srunner_create(suite);
  srunner_run_all(runner, CK_VERBOSE);
  number_failed = srunner_ntests_failed(runner);
  srunner_free(runner);
  return number_failed;
}


