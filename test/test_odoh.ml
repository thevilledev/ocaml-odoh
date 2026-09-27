let () =
  Alcotest.run "odoh"
    [
      ("known answer", Test_known_answer.tests);
      ("config", Test_config.tests);
      ("message", Test_message.tests);
      ("exchange", Test_exchange.tests);
      ("proxy", Test_proxy.tests);
      ("service", Test_service.tests);
      ("differential", Test_differential.tests);
      ("properties", Test_properties.tests);
    ]
