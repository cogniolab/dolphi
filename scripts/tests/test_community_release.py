"""Public-export regressions: private-state exclusion, integrity and fail-closed checks."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from check_community_release import selected,validate
from export_community import export


class CommunityRelease(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='dolphi-public-export-test-')
        self.addCleanup(self.temporary.cleanup)
        self.area=Path(self.temporary.name);self.root=self.area/'source';self.root.mkdir()
        for folder in ['release','src','experiments/sqlcipher']:(self.root/folder).mkdir(parents=True)
        (self.root/'README.md').write_text('# Preview\n\n[Source](src/lib.rs)\n')
        (self.root/'Cargo.lock').write_text('# synthetic lock\n')
        (self.root/'src/lib.rs').write_text('// synthetic source\n')
        # A deliberately tiny native-check executable isolates packaging logic;
        # real native integrity is run separately by CI and the actual exporter.
        (self.root/'experiments/sqlcipher/check_build.py').write_text('raise SystemExit(0)\n')
        self.config=dict(repository=None,maintainer_contact=None,security_email=None,private_vulnerability_reporting_verified=False)
        self.policy=dict(schema=1,files=['README.md','Cargo.lock','release/community.json','release/public-files.json','experiments/sqlcipher/check_build.py'],directories=['src'])
        self.save()

    def save(self):
        (self.root/'release/community.json').write_text(json.dumps(self.config))
        (self.root/'release/public-files.json').write_text(json.dumps(self.policy))

    def test_prepared_tree_is_distinct_from_publication_ready(self):
        result=validate(self.root)
        self.assertEqual(result['status'],'passed');self.assertFalse(result['publish_ready'])
        self.config.update(repository='example/dolphi',maintainer_contact='maintainer@example.invalid',security_email='security@example.invalid');self.save()
        self.assertTrue(validate(self.root)['publish_ready'])

    def test_unknown_private_files_are_not_exported(self):
        private=self.root/'docs/evidence';private.mkdir(parents=True)
        (private/'private.json').write_text(json.dumps({'secret':'ghp_'+'A'*36}))
        output=self.area/'public';export(self.root,output)
        self.assertFalse((output/'docs/evidence').exists());self.assertEqual(validate(output,strict=True)['status'],'passed')

    def test_added_secret_in_public_source_is_rejected(self):
        (self.root/'src/leak.rs').write_text('// '+'ghp_'+'A'*36)
        self.assertTrue(any('github_token' in e for e in validate(self.root)['errors']))
        with self.assertRaisesRegex(ValueError,'public_source_validation_failed'):export(self.root,self.area/'public')

    def test_private_state_in_selected_directory_is_rejected(self):
        (self.root/'src/private.token').write_text('synthetic')
        self.assertTrue(any('private_state_file' in e for e in validate(self.root)['errors']))

    def test_environment_file_is_rejected(self):
        (self.root/'src/.env').write_text('TOKEN=synthetic')
        self.assertTrue(any('private_state_file' in e for e in validate(self.root)['errors']))

    def test_symlink_parent_of_explicit_file_is_rejected(self):
        (self.root/'alias').symlink_to(self.root/'src',target_is_directory=True)
        self.policy['files'].append('alias/lib.rs');self.save()
        with self.assertRaisesRegex(ValueError,'invalid_public_file'):selected(self.root)

    def test_personal_installation_path_is_rejected(self):
        (self.root/'src/lib.rs').write_text('// '+('/home/'+'alice/private'))
        self.assertTrue(any('personal_home_path' in e for e in validate(self.root)['errors']))

    def test_missing_and_omitted_local_links_are_rejected(self):
        (self.root/'README.md').write_text('[Missing](absent.md)\n')
        self.assertTrue(any('missing local link' in e for e in validate(self.root)['errors']))
        (self.root/'hidden.md').write_text('# Hidden\n');(self.root/'README.md').write_text('[Hidden](hidden.md)\n')
        self.assertTrue(any('link omitted' in e for e in validate(self.root)['errors']))

    def test_symlink_and_parent_traversal_are_rejected(self):
        (self.root/'src/alias').symlink_to(self.root/'README.md')
        with self.assertRaisesRegex(ValueError,'invalid_public_file'):selected(self.root)
        (self.root/'src/alias').unlink();self.policy['files'].append('../outside');self.save()
        with self.assertRaisesRegex(ValueError,'invalid_public_file'):selected(self.root)

    def test_native_check_failure_blocks_release(self):
        (self.root/'experiments/sqlcipher/check_build.py').write_text('raise SystemExit(1)\n')
        self.assertIn('native_source_integrity_failed',validate(self.root)['errors'])

    def test_existing_destination_is_preserved(self):
        output=self.area/'public';output.mkdir();(output/'keep').write_text('keep')
        with self.assertRaisesRegex(ValueError,'destination_must_be_new'):export(self.root,output)
        self.assertEqual((output/'keep').read_text(),'keep')

    def test_manifest_detects_post_export_modification(self):
        output=self.area/'public';export(self.root,output)
        (output/'src/lib.rs').write_text('// changed\n')
        self.assertTrue(any('public_manifest_hash_changed' in e for e in validate(output)['errors']))

    def test_strict_export_rejects_extra_file(self):
        output=self.area/'public';export(self.root,output);(output/'unexpected').write_text('x')
        self.assertTrue(any('unallowlisted_export_file' in e for e in validate(output,strict=True)['errors']))


if __name__=='__main__':unittest.main()
