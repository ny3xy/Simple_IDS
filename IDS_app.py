from ids import IDS
from ids.rule import RuleReader
import logging

def setup_logging():
    logger = logging.getLogger('Simple_IDS')
    logger.setLevel(logging.DEBUG)  # Set the logging level

    # file handler to log to a file
    file_handler = logging.FileHandler('ids.log')
    file_handler.setLevel(logging.INFO)  # Log INFO and above to the file

    #logging format
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

def main():
    setup_logging()
    logger = logging.getLogger('Simple_IDS')
    try:
        logger.info('IDS started...')
        rules = RuleReader.read('rules.txt')
        ids = IDS(rules)
        ids.start()
    except (KeyboardInterrupt, SystemExit):
        logger.info('Gracefully shutdown from KeyboardInterrupt')
    except Exception as e:
        logger.info(f'Uncaught exception: {e}')
    finally:
        ids.stop()
        ids.join()

if __name__ == '__main__':
    main()
