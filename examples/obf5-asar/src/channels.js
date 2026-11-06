// 通道名单独放一个文件，主进程那边只 import 进来用。
// 一个文件一个文件地扫，永远配不上这种。
const VAULT_UNLOCK_CHANNEL = 'vault:unlock';
const VAULT_EXPORT_CHANNEL = 'vault:__export_all';

module.exports = { VAULT_UNLOCK_CHANNEL, VAULT_EXPORT_CHANNEL };
