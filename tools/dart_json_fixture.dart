// Regenerate: dart run tools/dart_json_fixture.dart contract/report-1/android-8-ios-5/samples > tests/NecessarySdk.Tests/Fixtures/dart_json_fixture.json
// Writes what Dart's jsonEncode makes of the contract's samples and of edge
// values, so the .NET encoder can be held to it byte for byte.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

String bits(double d) {
  final data = ByteData(8)..setFloat64(0, d);
  return data.getUint64(0).toRadixString(16).padLeft(16, '0');
}

void main(List<String> args) {
  final samples = Directory(args[0]).listSync().whereType<File>().where((f) => f.path.endsWith('.json')).toList()
    ..sort((a, b) => a.path.compareTo(b.path));
  final cases = <Map<String, dynamic>>[];
  for (final f in samples) {
    final sample = jsonDecode(f.readAsStringSync()) as Map<String, dynamic>;
    cases.add({'name': f.uri.pathSegments.last, 'dart': jsonEncode(sample['report'])});
  }
  final strings = <String>[
    'café / €', '"x"', 'tab\tnew\nline\rcr\bback\fform', '\u0001\u001f\u007f', 'emoji \u{1F600}',
    '  ', '<>&\'+=', 'a/b\\c', ' nbsp', 'märz –',
  ];
  for (final s in strings) {
    cases.add({'name': 'string', 'dart': jsonEncode({'s': s, 'l': [s]})});
  }
  final doubles = <double>[
    0.0, -0.0, 1.0, -1.0, 0.1, 1e-6, 1e-7, 1.5e-7, 123.456, 1e15, 1e20, 1e21, 1.2345678901234567e19,
    1.7976931348623157e308, 5e-324, 31.5204, 74.3587, 12.0, 0.000123, 100.0, 2.5e-5, 4.35, 0.30000000000000004,
    123456789.125, 1e-5, 9.999999999999999e20, 6.02214076e23, -2.5e-8,
  ];
  final doubleCases = <Map<String, dynamic>>[];
  for (final d in doubles) {
    doubleCases.add({'bits': bits(d), 'dart': jsonEncode(d)});
  }
  final ints = <int>[0, -1, 9007199254740993, 9223372036854775807, -9223372036854775808];
  for (final i in ints) {
    cases.add({'name': 'int', 'dart': jsonEncode({'i': i})});
  }
  final targets = <String>[
    '/v1/x?a=b', '/v1/a b?c d', '/v1/%7euser?q=%2b%41', '/v1/../x/./y?z#frag', '/v1/[x]?{y}|^`',
    '/v1/caf\u00e9?q=\u20ac', '/v1/x?', '/a/%zz?%', '/v1/x%2Fy?a%2Fb', '/v1/x?a=1&b=2;c', '/v1/x??y',
    '/v1/auth/approvals?limit=5&state=pending', '/v1/business/graph?handle=a%20b%2Bc', '/x/y/..', '/x/.',
    "/v1/!\$&'()*+,;=:@?/?:@!\$&'()*+,;=", '/v1/x\\y?a\\b', '/v1/x?a=\u{1F600}', '/v1/"q"?"r"',
  ];
  final targetCases = <Map<String, dynamic>>[];
  for (final t in targets) {
    final uri = Uri.parse(t);
    targetCases.add({'target': t, 'path': uri.path, 'query': uri.query});
  }
  stdout.write(const JsonEncoder.withIndent(' ').convert({
    'targets': targetCases,
    'about': 'Made by Dart ${Platform.version.split(' ').first} jsonEncode: the bytes the Flutter plugin sends. tests/NecessarySdk.Tests/DartJsonTests.cs holds the .NET encoder to them.',
    'cases': cases,
    'doubles': doubleCases,
  }));
}
