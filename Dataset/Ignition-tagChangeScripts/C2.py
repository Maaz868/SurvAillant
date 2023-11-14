def valueChanged(tag, tagPath, previousValue, currentValue, initialChange, missedEvents):
#		system.tag.write('[default]CloseLoad2', False)
		current_value = currentValue.value
		lower_boundary = 8000
		upper_boundary = 24000
					
		if current_value < lower_boundary or current_value > upper_boundary:
		    system.tag.write('[default]CloseLoad2', True)
					