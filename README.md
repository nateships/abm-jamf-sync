# ABM to Jamf Purchasing Sync

A GitHub Action that copies order and AppleCare data from **Apple Business Manager** or **Apple School Manager** into the **Purchasing** fields of Jamf Pro. It runs on a GitHub-hosted Linux runner. You do not need a Mac or a GSX account.

## What it does

1. Reads computers and mobile devices from Jamf Pro.
2. Reads your organization devices from the Apple Business Manager API (or Apple School Manager API).
3. For each Jamf device that is in ABM, gets its AppleCare coverage.
4. Writes only the fields that changed. It never clears a field.

| Jamf field | Source in ABM |
|---|---|
| PO Number | `orderNumber` (the Apple or reseller order number) |
| PO Date | `orderDateTime` |
| Vendor | `Apple` for Apple purchases. For reseller purchases, the name from `vendor-map`. |
| Warranty Expiration | Latest end date of the coverage that is not canceled |
| AppleCare ID | `agreementNumber` of the AppleCare plan |
| Purchased | `true` for Apple and reseller purchases (off by default) |

ABM has no purchase price, lease, or contact data. Use Jamf Inventory Preload for those fields, and leave them out of `fields`.

### Devices that are not in ABM

The ABM API returns only the devices in your organization. For a Mac that is not in ABM, you can set `warranty-ea-name` to the name of a computer extension attribute that has a warranty date. The sync then copies that date into Warranty Expiration. [Extension attribute example](#warranty-extension-attribute)

## Quick start

1. **Apple Business Manager:** an Administrator [creates an API account](https://support.apple.com/guide/business/axm33189f66a). Keep the client ID, the key ID, and the private key. (Apple School Manager: [create an API account](https://support.apple.com/guide/apple-school-manager/axm33189f66a).)
2. **Jamf Pro:** create an API role with these privileges, then an API client with that role:
   - Read Computers, Update Computers
   - Read Mobile Devices, Update Mobile Devices (only if you set `device-types` to include `mobile`)
3. **GitHub:** in a **private** repository, create an environment named `jamf` with these secrets and variables:

   | Name | Type | Value |
   |---|---|---|
   | `JAMF_URL` | variable | `https://yourorg.jamfcloud.com` |
   | `JAMF_CLIENT_ID` | secret | Jamf API client ID |
   | `JAMF_CLIENT_SECRET` | secret | Jamf API client secret |
   | `AXM_CLIENT_ID` | secret | `BUSINESSAPI.…` |
   | `AXM_KEY_ID` | secret | Key ID |
   | `AXM_PRIVATE_KEY` | secret | Contents of the `.pem` file |
   | `DRY_RUN` | variable | `true` until you trust the output |
   | `VENDOR_MAP` | variable | Optional, see below |

4. Copy [`examples/sync.yml`](examples/sync.yml) to `.github/workflows/` in that repository.

### Roll out safely

1. Run the workflow by hand with `dry-run` on. Read the planned changes in the step summary.
2. Run it with `dry-run` off and `serials` set to **one** test device. In Jamf Pro, check that the device got the new values and that its other purchasing fields (price, lease, contact) did not change.
3. Set the `DRY_RUN` variable to `false`. The schedule then writes for the whole fleet.

## Inputs

| Input | Default | Description |
|---|---|---|
| `jamf-url` | | Jamf Pro URL |
| `jamf-client-id` | | Jamf API client ID |
| `jamf-client-secret` | | Jamf API client secret |
| `axm-client-id` | | ABM or ASM API client ID |
| `axm-key-id` | | Key ID of the API private key |
| `axm-private-key` | | Private key (PEM) |
| `axm-scope` | `business` | `business` or `school` |
| `dry-run` | `true` | Log the changes and write nothing |
| `fields` | `poNumber,poDate,vendor,warrantyDate,appleCareId` | Fields that the sync manages. Also available: `purchased` |
| `device-types` | `computers` | Jamf device types to sync: `computers`, `mobile`, or `computers,mobile`. Mobile needs the mobile device privileges. |
| `vendor-map` | `{}` | JSON that maps an ABM `purchaseSourceUid` to a vendor name |
| `warranty-ea-name` | | Computer extension attribute with a warranty date, for Macs not in ABM |
| `serials` | | Only these serial numbers |
| `fail-on-error` | `true` | Fail the step when a device update fails |

Outputs: `jamf-devices`, `matched-abm`, `matched-ea`, `no-data`, `unsupported`, `unchanged`, `changed`, `errors`.

### Vendor map

ABM identifies a reseller only by an ID (`purchaseSourceUid`). The sync skips the Vendor field for a reseller that is not in the map. To find the ID, call the ABM API for one device from that reseller, then map it:

```json
{"-2085650007946880": "Example Reseller"}
```

### Fields that you manage somewhere else

If Inventory Preload or a person sets your internal PO number, leave `poNumber` out of `fields`, so the ABM order number does not replace it.

## Warranty extension attribute

macOS 13 and later keeps the AppleCare status of the Mac when a user is signed in with an Apple Account. This extension attribute (data type **Date**) reads it:

```bash
#!/bin/zsh
# Report the AppleCare expiration date for this Mac.
# macOS caches the coverage data when a user signs in with an Apple Account.

serial=$(/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice | /usr/bin/awk -F'"' '/IOPlatformSerialNumber/{print $4}')
result=""

for home in /Users/*(N/); do
  file="$home/Library/Application Support/com.apple.NewDeviceOutreach/caches/coverageDetails/${serial}.json"
  [[ -f "$file" ]] || continue
  epoch=$(/usr/bin/plutil -extract settingsCoverageSection.offer.expiration raw -o - "$file" 2>/dev/null)
  if [[ "$epoch" == <-> ]] && (( epoch > 0 )); then
    result=$(/bin/date -r "$epoch" "+%Y-%m-%d %H:%M:%S")
    break
  fi
done

echo "<result>${result}</result>"
```

Apple does not document this file. Compare the result with System Settings > General > AppleCare & Warranty on a few Macs before you rely on it.

## Requirements

- The latest Jamf Pro release. The action uses the computer inventory API v4 and the mobile device API v2.
- watchOS and visionOS devices are counted as `unsupported`. The Jamf mobile device API cannot update their purchasing fields.

## Development

The repository uses [mise](https://mise.jdx.dev) for its tools.

```bash
mise install
mise run check   # lint and test
```

## Limits

- This is not an Apple or Jamf product. Test it on your own data before you trust it.
- Apple and Jamf can change their APIs. A change can make the sync fail or skip a field.
