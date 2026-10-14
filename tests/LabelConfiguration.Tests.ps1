BeforeAll {
    $root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    Import-Module (Join-Path $root 'src\PurviewIPAsCode\PurviewIPAsCode.psd1') -Force
}

Describe 'Source-controlled label conditions and container protections' {
    It 'matches title-case access headings without an implicit case-insensitive test override' {
        $detection = Get-Content (Join-Path $root 'config\detection.json') -Raw | ConvertFrom-Json
        $text = [IO.File]::ReadAllText((Join-Path $root 'demo\content\generated\bcsi-access.txt'))
        foreach ($pattern in ($detection.detectors | Where-Object key -eq 'bcsi-access-procedures').patterns) {
            [regex]::IsMatch($text, $pattern.primaryRegex) | Should -BeTrue
            foreach ($support in $pattern.supportRegexes) {
                [regex]::IsMatch($text, $support) | Should -BeTrue
            }
        }
    }
    It 'plans all labels without connecting or mutating the tenant' {
        $plan = @(Invoke-PurviewLabelConfiguration -EnvironmentPath 'config\environments\demo.example.json')
        $plan.Count | Should -Be 10
        @($plan | Where-Object { $_.Arguments.ContainsKey('Conditions') }).Count | Should -Be 3
        foreach ($entry in $plan) {
            $entry.Arguments.ContentType | Should -Be 'File, Email, Site, UnifiedGroup'
        }
    }

    It 'uses the 1-199 and 200+ boundaries with automatic rather than recommended application' {
        $plan = @(Invoke-PurviewLabelConfiguration -EnvironmentPath 'config\environments\demo.example.json')
        foreach ($key in 'confidential-internal', 'highly-confidential-internal') {
            $document = ($plan | Where-Object Key -eq $key).Arguments.Conditions | ConvertFrom-Json
            $leaf = $document.And[0].Or[0]
            $leaf.Value | Should -Be 'a44669fe-0d48-453d-a9b1-2cc83f2cba77'
            $settings = @{}
            foreach ($setting in $leaf.Settings) { $settings[$setting.Key] = $setting.Value }
            $settings.minconfidence | Should -Be '85'
            $settings.ContainsKey('autoapplytype') | Should -BeFalse
            if ($key -eq 'confidential-internal') {
                $settings.mincount | Should -Be '1'
                $settings.maxcount | Should -Be '199'
            }
            else {
                $settings.mincount | Should -Be '200'
                $settings.maxcount | Should -Be '-1'
            }
        }
    }

    It 'combines the three BES detectors with OR rather than requiring all three' {
        $plan = @(Invoke-PurviewLabelConfiguration -EnvironmentPath 'config\environments\demo.example.json')
        $document = ($plan | Where-Object Key -eq 'highly-confidential-bes').Arguments.Conditions | ConvertFrom-Json
        $document.And.Count | Should -Be 1
        $document.And[0].Or.Count | Should -Be 3
        @($document.And[0].Or.Value | Select-Object -Unique).Count | Should -Be 3
    }

    It 'does not assign scanner auto conditions to user-defined recipient labels' {
        $plan = @(Invoke-PurviewLabelConfiguration -EnvironmentPath 'config\environments\demo.example.json')
        foreach ($entry in ($plan | Where-Object Key -like '*recipients')) {
            $entry.Arguments.ContainsKey('Conditions') | Should -BeFalse
        }
    }

    It 'leaves low-tier container controls untouched and applies the approved higher-tier profile' {
        $plan = @(Invoke-PurviewLabelConfiguration -EnvironmentPath 'config\environments\demo.example.json')
        foreach ($entry in ($plan | Where-Object Key -in @('public', 'non-business', 'general'))) {
            $entry.Arguments.ContainsKey('SiteAndGroupProtectionEnabled') | Should -BeFalse
        }
        $confidential = ($plan | Where-Object Key -eq 'confidential-internal').Arguments
        $confidential.SiteAndGroupProtectionPrivacy | Should -Be 'Private'
        $confidential.SiteAndGroupProtectionAllowAccessToGuestUsers | Should -BeTrue
        $confidential.SiteExternalSharingControlType | Should -Be 'ExistingExternalUserSharingOnly'
        $bes = ($plan | Where-Object Key -eq 'highly-confidential-bes').Arguments
        $bes.SiteAndGroupProtectionPrivacy | Should -Be 'Private'
        $bes.SiteAndGroupProtectionAllowAccessToGuestUsers | Should -BeFalse
        $bes.SiteExternalSharingControlType | Should -Be 'Disabled'
    }

    It 'ignores JSON ordering but detects condition thresholds and recommendation drift' {
        InModuleScope PurviewIPAsCode {
            $definitions = Get-PurviewDefinition 'config\environments\demo.example.json'
            $label = $definitions.Labels | Where-Object key -eq 'confidential-internal'
            $expected = Get-PurviewLabelConfigurationArgument -Label $label -Definitions $definitions
            $document = $expected.Conditions | ConvertFrom-Json -AsHashtable
            $leaf = $document.And[0].Or[0]
            $leaf.Settings = @($leaf.Settings | Sort-Object Key -Descending)
            Get-PurviewConditionSignature ($document | ConvertTo-Json -Depth 12) |
                Should -Be (Get-PurviewConditionSignature $expected.Conditions)
            $leaf.Settings += @{ Key = 'autoapplytype'; Value = 'Recommend' }
            Get-PurviewConditionSignature ($document | ConvertTo-Json -Depth 12) |
                Should -Not -Be (Get-PurviewConditionSignature $expected.Conditions)
            { Get-PurviewConditionSignature '{"Or":[]}' } | Should -Throw '*Unsupported*'
            { Get-PurviewConditionSignature 'invalid json' } | Should -Throw
        }

    }
    It 'preserves additional label scopes while detecting missing requested scopes' {
        InModuleScope PurviewIPAsCode {
            $expected = @{ ContentType = 'File, Email, Site, UnifiedGroup' }
            $actual = @{ ContentType = 'File, Email, Site, UnifiedGroup, Teamwork' }
            Test-PurviewLabelConfigurationMatch -Actual $actual -Expected $expected | Should -BeTrue
            $actual.ContentType = 'File, Email, Teamwork'
            Test-PurviewLabelConfigurationMatch -Actual $actual -Expected $expected | Should -BeFalse
        }
    }
}
