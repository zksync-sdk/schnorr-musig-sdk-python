import yaml
import importlib.resources as pkg_resources

class LoggerConfig:

  @staticmethod
  def console(verbosity: int = 0) -> dict:
    stream = pkg_resources.open_binary('zksync.config', 'console.yaml')
    config = yaml.load(stream, Loader=yaml.FullLoader)
    config['loggers']['zksync']['level'] = LoggerConfig.level(verbosity)
    config['loggers']['__main__']['level'] = LoggerConfig.level(verbosity)
    return config

  @staticmethod
  def level(verbosity: int = 0) -> int:
    '''
    Converts int to a log level. Default level is logging.Warning.
    logging.DEBUG(2) - logging.INFO(1) - logging.WARNING(0=default)
    '''
    return 30 - min(verbosity, 2) * 10